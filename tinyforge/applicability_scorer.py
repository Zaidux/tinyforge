"""Applicability-aware scorer — the deterministic baseline the model must beat.

The first version of the scorer scored **0.000 precision and 0.000 recall**
against applicability-derived ground truth. The cause was structural, not
incidental: it judged technique coverage by string-matching tool names, and
never received the technique catalogue at all. It was structurally incapable
of the task.

This module fixes that by making the applicability function the scorer. That
is the right design for a *deterministic* baseline, because the gate is
itself deterministic and auditable — and it sets the bar honestly. A learned
scorer has to beat a scorer that already knows the applicability rules.

## Known defect: tool-name-only inference

**This scorer infers coverage from tool-name intersection, and that is a
real limitation, not a caveat.** An agent can genuinely test authentication
using `curl` rather than a dedicated auth tool, and this scorer will report
that authentication was never tested. It is not lying; it lacks the evidence.

An external review named this failure mode precisely, and it is the clearest
specification we have for what a learned component is *for*: inferring
coverage from **reasoning text** where the tool log is silent.

The two inference paths are kept explicit in :class:`Evidence` so the gap is
measurable rather than hidden. Track ``via_reasoning`` alongside the
tool-derived set; the difference between them is precisely the cases a
learned scorer would need to recover.

## Levels evaluated separately

Mixing them produced a misleading 0.000: hallucination gaps were counted as
technique false positives. They are different decisions with different
failure costs, and PRISM's asymmetry argument applies to each separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .applicability import CATALOGUE, TargetProfile, applicable, coverage_matrix
from .blindspot import find_ungrounded_claims

__all__ = [
    "ApplicabilityScorer",
    "ScoredCase",
    "Evidence",
    "score_case",
    "REASONING_MARKERS",
]


#: Phrases that indicate a technique was *reasoned about* even when no
#: conventional tool was invoked. Deliberately narrow — a loose marker list
#: would turn the reasoning path into a second source of false positives,
#: which is the damaging direction.
REASONING_MARKERS: dict[str, tuple[str, ...]] = {
    "auth_session": ("authentication", "login", "session", "credential",
                     "password", "brute force"),
    "sql_injection": ("sql injection", "sqli", "sql query", "union select"),
    "nosql_injection": ("nosql", "mongodb injection", "operator injection"),
    "xss_reflected": ("xss", "cross-site scripting", "cross site scripting"),
    "xss_stored": ("stored xss", "persistent xss"),
    "ssrf": ("ssrf", "server-side request forgery", "server side request forgery"),
    "xxe": ("xxe", "xml external entity"),
    "csrf": ("csrf", "cross-site request forgery", "cross site request forgery"),
    "idor": ("idor", "insecure direct object", "bola", "broken object level",
             "horizontal privilege"),
    "bfa": ("broken function level", "bfla", "vertical privilege",
            "privilege escalation check"),
    "file_upload": ("file upload", "unrestricted upload", "upload endpoint"),
    "ssti": ("ssti", "template injection", "server-side template"),
    "deserialization": ("deserializ", "unmarshal", "pickle"),
    "jwt": ("jwt", "json web token", "algorithm confusion", "alg=none"),
    "cors": ("cors", "cross-origin resource sharing"),
    "command_injection": ("command injection", "os command", "shell injection"),
    "rce": ("remote code execution", "arbitrary code execution", "rce",
            "code execution"),
    "path_traversal": ("path traversal", "directory traversal",
                       "arbitrary file read"),
    "recon": ("subdomain enumeration", "endpoint discovery", "port scan"),
    "port_scan": ("port scan", "service enumeration", "nmap"),
    "config_review": ("misconfiguration", "security header", "default credential"),
    "race_condition": ("race condition", "toctou", "time-of-check"),
    "business_logic": ("business logic", "workflow bypass", "price manipulation"),
}


@dataclass
class Evidence:
    """Where a coverage judgement came from.

    Keeping both paths explicit makes the tool-name limitation measurable:
    ``via_reasoning - via_tools`` is the set a learned scorer would need to
    recover from reasoning text alone.
    """

    via_tools: frozenset[str] = frozenset()
    via_reasoning: frozenset[str] = frozenset()

    @property
    def covered(self) -> frozenset[str]:
        return self.via_tools | self.via_reasoning

    @property
    def reasoning_only(self) -> frozenset[str]:
        """Covered by reasoning but invisible to tool-name matching."""
        return self.via_reasoning - self.via_tools

    def as_dict(self) -> dict:
        return {
            "via_tools": sorted(self.via_tools),
            "via_reasoning": sorted(self.via_reasoning),
            "reasoning_only": sorted(self.reasoning_only),
        }


@dataclass
class ScoredCase:
    """One scorer verdict against one case."""

    case_id: str
    #: Technique ids the scorer says are applicable but untested.
    technique_gaps: frozenset[str]
    #: Tools available but never invoked.
    tool_gaps: frozenset[str]
    #: Claimed ungrounded finding assertions.
    hallucination_flags: int
    #: Why each technique gap was flagged.
    reasons: dict[str, list[str]] = field(default_factory=dict)
    abstained: bool = False
    caveat: str = ""
    #: Provenance of the coverage judgement.
    evidence: Evidence = field(default_factory=Evidence)


class ApplicabilityScorer:
    """Deterministic scorer grounded in the applicability function.

    Conservative by construction. It reports a technique gap only when the
    technique is genuinely applicable and no conventional tool for it appears
    in the trajectory. Because applicability defaults to "unknown facts
    enable nothing", an under-specified target yields *fewer* flags — the
    correct direction, given false positives are the damaging error.
    """

    def __init__(self, *, min_coverage_before_flagging: float = 0.0) -> None:
        self.min_coverage_before_flagging = min_coverage_before_flagging

    def score(
        self,
        case_id: str,
        profile: TargetProfile,
        attempted: Sequence[str],
        trajectory_text: str = "",
        *,
        use_reasoning: bool = True,
    ) -> ScoredCase:
        """Score coverage for one case.

        *trajectory_text* is the agent's own reasoning. When
        *use_reasoning* is on, techniques mentioned in the text count as
        covered even if no conventional tool was invoked — which is the
        documented mitigation for the tool-name limitation.

        Set ``use_reasoning=False`` to measure the defect directly: the
        difference between the two is the recovery a learned scorer offers.
        """
        matrix = coverage_matrix(profile, attempted)

        coverage = matrix["coverage"]
        if coverage < self.min_coverage_before_flagging:
            return ScoredCase(
                case_id=case_id,
                technique_gaps=frozenset(),
                tool_gaps=frozenset(),
                hallucination_flags=0,
                abstained=True,
                caveat=f"coverage {coverage:.0%} below threshold",
            )

        tool_covered = frozenset(matrix["covered"])
        text = (trajectory_text or "").lower()
        reasoning_covered = frozenset(
            tech
            for tech in applicable(profile)
            if any(marker in text for marker in REASONING_MARKERS.get(tech, ()))
        )

        evidence = Evidence(via_tools=tool_covered, via_reasoning=reasoning_covered)
        covered = evidence.covered if use_reasoning else tool_covered

        technique_gaps = frozenset(matrix["gaps"].keys()) - covered
        reasons = {k: v["why_applicable"] for k, v in matrix["gaps"].items() if k in technique_gaps}

        expected_tools = set(profile.tools)
        tool_gaps = frozenset(expected_tools - set(attempted))

        claims = find_ungrounded_claims(trajectory_text or "")

        return ScoredCase(
            case_id=case_id,
            technique_gaps=technique_gaps,
            tool_gaps=tool_gaps,
            hallucination_flags=sum(1 for c in claims if not c.grounded),
            reasons=reasons,
            evidence=evidence,
        )
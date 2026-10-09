"""Strategy-coverage blind-spot detection.

Tool coverage (see :mod:`tinyforge.coverage`) asks "what did the agent not
run?" That is necessary but not sufficient: an agent can run every scanner
and still test nothing. What is missing is **strategy** — the reasoning
about what to attempt — which is exactly where a small model is *weakest*
and therefore where blind-spot detection has the most value if it works.

This module detects **blind spots**, defined as capabilities present in the
model's own repertoire that the trajectory never engaged, at three levels:

``tool``        a tool was never invoked
``technique``   a vuln class was never targeted
``hypothesis``  a testable claim was never considered

The distinction is not cosmetic. Tools are enumerable and cheap to audit.
Techniques and hypotheses require *judging whether the agent's reasoning
covered a class of attack* — which is a semantic comparison, and therefore
closer to the boundary where T1 found small models failing.

**The honest limitation, stated up front:** judging technique coverage
reliably needs semantic understanding, which is precisely what a 20M model
lacks. So this module deliberately separates:

* :func:`structural_gaps` — deterministic, no model needed, catches tool
  and enum-level gaps. This is what ships first.
* :class:`BlindSpotDetector` — the learned scorer interface, with a
  heuristic stand-in so the pipeline is testable before a model exists.

The heuristic is **not** presented as the model. It exists to be beaten, and
to make the evaluation harness runnable today.

## Why "reduced hallucination" belongs here

A hallucination in an agent trajectory has a specific, checkable form: the
agent asserts a finding, a technique, or a conclusion with no supporting
evidence in the trajectory. That is an **ungrounded claim**, and it is
detectable from structure alone — claim present, evidence absent — with no
semantic judgement required.

That makes hallucination detection a *better* fit for a small scorer than
reasoning-quality judgement: the evidence check is mechanical, and only the
final severity weighting needs judgement. See
:func:`find_ungrounded_claims`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

__all__ = [
    "Level",
    "Gap",
    "BlindSpotReport",
    "structural_gaps",
    "BlindSpotDetector",
    "Claim",
    "find_ungrounded_claims",
    "hallucination_report",
]


class Level:
    """Gap granularity. Higher is more abstract and harder to detect."""

    TOOL = "tool"
    TECHNIQUE = "technique"
    HYPOTHESIS = "hypothesis"


@dataclass(frozen=True)
class Gap:
    """One thing the agent never tried."""

    level: str
    name: str
    reason: str
    severity: float
    #: Why this was flagged — needed so a human can audit the heuristic.
    evidence: str = ""

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "name": self.name,
            "reason": self.reason,
            "severity": round(self.severity, 3),
            "evidence": self.evidence,
        }


@dataclass
class BlindSpotReport:
    """All gaps found for one trajectory."""

    gaps: tuple[Gap, ...] = ()
    abstained: bool = False
    caveat: str = ""

    def by_level(self, level: str) -> tuple[Gap, ...]:
        return tuple(g for g in self.gaps if g.level == level)

    @property
    def levels_present(self) -> tuple[str, ...]:
        seen = {g.level for g in self.gaps}
        return tuple(l for l in (Level.TOOL, Level.TECHNIQUE, Level.HYPOTHESIS)
                     if l in seen)

    def as_dict(self) -> dict:
        return {
            "abstained": self.abstained,
            "caveat": self.caveat,
            "counts": {lvl: len(self.by_level(lvl)) for lvl in self.levels_present},
            "gaps": [g.as_dict() for g in self.gaps],
        }


# ── Structural (deterministic) detection ───────────────────────────────────


def structural_gaps(
    attempted: Iterable[str],
    available: Iterable[str],
    *,
    techniques_available: Mapping[str, Sequence[str]] | None = None,
    required: Iterable[str] = (),
    excluded: Iterable[str] = (),
) -> BlindSpotReport:
    """Deterministic blind-spot detection. No model required.

    Parameters
    ----------
    attempted, available:
        Tool names.
    techniques_available:
        ``{technique_name: [tool or indicator strings]}``. A technique is
        considered *covered* if any of its indicators appears in
        ``attempted`` or in ``trajectory_text`` passed as
        ``technique_evidence``.
    required:
        Tools mandatory for completion; missing ones are severity 1.0.

    Notes
    -----
    Technique coverage here is **string matching**, not semantic judgement.
    That is a real limitation and is why severity for technique gaps caps
    below 1.0 — these are hints for a human or a learned scorer to confirm,
    not confident claims.
    """
    attempted_set = set(attempted)
    available_set = set(available) - set(excluded)
    excluded_set = set(excluded)
    gaps: list[Gap] = []

    # Required tools — the strongest structural signal.
    for tool in required:
        if tool not in attempted_set and tool not in excluded_set:
            gaps.append(
                Gap(Level.TOOL, tool, "required but never invoked", 1.0,
                    evidence="required set")
            )

    # Available-but-unused tools.
    for tool in sorted(available_set - attempted_set):
        gaps.append(
            Gap(Level.TOOL, tool, "available but never invoked", 0.5,
                evidence="tool inventory")
        )

    # Techniques: covered if any indicator was attempted.
    for technique, indicators in (techniques_available or {}).items():
        if any(ind in attempted_set for ind in indicators):
            continue
        if set(indicators) & excluded_set:
            continue
        gaps.append(
            # Capped below 1.0: string matching cannot confirm a technique
            # was untried, only that no indicator surfaced.
            Gap(Level.TECHNIQUE, technique,
                "no indicator of this technique appeared in the trajectory",
                0.4, evidence=f"indicators={list(indicators)}")
        )

    return BlindSpotReport(gaps=tuple(gaps))


# ── Ungrounded claims (hallucination) ──────────────────────────────────────

#: Phrases that assert a finding without necessarily carrying evidence.
#: Matched case-insensitively.
_CLAIM_PATTERNS = (
    r"\b(?:found|identified|discovered|confirmed)\b[^.\n]{0,60}\b"
    r"(?:vulnerability|vuln|CVE|XSS|SQLi|injection|RCE|traversal|SSRF)\b",
    r"\bthis (?:is|appears to be) (?:a|an)\b[^.\n]{0,40}"
    r"(?:vulnerability|exploit|bypass|flaw)\b",
    r"\bexploit(?:able|ation)? (?:is|was) (?:possible|confirmed|successful)\b",
    r"\b(?:the )?(?:target|host|endpoint) is vulnerable\b",
)

#: Evidence markers — a claim with none of these nearby is ungrounded.
_EVIDENCE_MARKERS = (
    "status code", "http/1", "http/2", "response body", "traceback",
    "curl", "status_code", "200", "403", "500", "payload", "request",
    "stack trace", "exit code", "stderr", "stdout", "evidence",
    "screenshot", "har", "packet", "pcap", "reproduced", "confirmed by",
)

_CLAIM_RE = re.compile("|".join(_CLAIM_PATTERNS), re.IGNORECASE)
_EVIDENCE_RE = re.compile("|".join(re.escape(m) for m in _EVIDENCE_MARKERS), re.IGNORECASE)


@dataclass
class Claim:
    """An asserted finding plus whether evidence supports it."""

    text: str
    grounded: bool
    nearest_evidence: str = ""

    def as_dict(self) -> dict:
        return {
            "text": self.text[:200],
            "grounded": self.grounded,
            "nearest_evidence": self.nearest_evidence[:120],
        }


def find_ungrounded_claims(text: str, *, window: int = 240) -> list[Claim]:
    """Find asserted findings with no evidence marker in context.

    Purely structural: claim pattern present, evidence marker absent within
    *window* characters. No semantic judgement, which is precisely why this
    suits a small scorer — the check is mechanical.

    This is a **high-recall, low-precision** filter. Absence of an evidence
    marker is not proof of hallucination; an agent may legitimately report a
    finding established earlier in a long trajectory. Treat output as
    "needs review", never as "this is false".
    """
    claims: list[Claim] = []
    for match in _CLAIM_RE.finditer(text or ""):
        start = match.start()
        left = max(0, start - window)
        right = min(len(text), start + len(match.group(0)) + window)
        context = text[left:right]

        found = _EVIDENCE_RE.search(context)
        claims.append(
            Claim(
                text=match.group(0),
                grounded=bool(found),
                nearest_evidence=found.group(0) if found else "",
            )
        )
    return claims


@dataclass
class HallucinationReport:
    """Ungrounded-claim accounting over a batch of trajectories."""

    total_claims: int
    grounded: int
    ungrounded: int
    trajectories_with_ungrounded: int
    trajectories: int

    @property
    def ungrounded_rate(self) -> float:
        return self.ungrounded / self.total_claims if self.total_claims else 0.0

    def as_dict(self) -> dict:
        return {
            "total_claims": self.total_claims,
            "grounded": self.grounded,
            "ungrounded": self.ungrounded,
            "ungrounded_rate": round(self.ungrounded_rate, 4),
            "trajectories": self.trajectories,
            "trajectories_with_ungrounded": self.trajectories_with_ungrounded,
            "trajectory_hit_rate": round(
                self.trajectories_with_ungrounded / self.trajectories, 4
            ) if self.trajectories else 0.0,
        }


def hallucination_report(trajectories: Sequence[str]) -> HallucinationReport:
    """Aggregate ungrounded claims across trajectories."""
    total = grounded = 0
    hits = 0
    for traj in trajectories:
        claims = find_ungrounded_claims(traj)
        if not claims:
            continue
        total += len(claims)
        ungrounded_here = 0
        for c in claims:
            if c.grounded:
                grounded += 1
            else:
                ungrounded_here += 1
        if ungrounded_here:
            hits += 1
    return HallucinationReport(
        total_claims=total,
        grounded=grounded,
        ungrounded=total - grounded,
        trajectories_with_ungrounded=hits,
        trajectories=len(trajectories),
    )


# ── Learned scorer interface ───────────────────────────────────────────────


class BlindSpotDetector:
    """Interface for the learned blind-spot scorer.

    Currently delegates to :func:`structural_gaps`. When a model exists it
    should replace the *technique* and *hypothesis* levels only — the tool
    level is exactly enumerated and a model would add cost without adding
    accuracy.

    The abstention path is load-bearing: a detector that confidently reports
    gaps on every trajectory is worse than none, because 55% of locally-good
    interventions degrade a previously-working case
    (arXiv:2609.24130). ``min_evidence_for_confidence`` is the guard.
    """

    def __init__(self, *, min_evidence_for_confidence: float = 0.3) -> None:
        self.min_evidence_for_confidence = min_evidence_for_confidence

    def detect(
        self,
        attempted: Iterable[str],
        available: Iterable[str],
        *,
        techniques_available: Mapping[str, Sequence[str]] | None = None,
        required: Iterable[str] = (),
        excluded: Iterable[str] = (),
        trajectory_text: str = "",
    ) -> BlindSpotReport:
        report = structural_gaps(
            attempted, available,
            techniques_available=techniques_available,
            required=required,
            excluded=excluded,
        )

        # Abstain when the trajectory is too thin to conclude anything.
        available_set = set(available) - set(excluded)
        if not available_set:
            return BlindSpotReport(
                gaps=(), abstained=True,
                caveat="no applicable capabilities to audit",
            )
        attempted_ratio = len(set(attempted) & available_set) / len(available_set)
        if attempted_ratio < self.min_evidence_for_confidence:
            return BlindSpotReport(
                gaps=(), abstained=True,
                caveat=(
                    f"coverage {attempted_ratio:.0%} below "
                    f"{self.min_evidence_for_confidence:.0%}: abstaining"
                ),
            )

        claims = find_ungrounded_claims(trajectory_text) if trajectory_text else []
        ungrounded = [c for c in claims if not c.grounded]
        if ungrounded:
            report.gaps = report.gaps + (
                Gap(
                    Level.HYPOTHESIS,
                    "ungrounded-finding-claim",
                    f"{len(ungrounded)} finding assertion(s) with no evidence marker",
                    0.6,
                    evidence=ungrounded[0].text[:120],
                ),
            )

        return report
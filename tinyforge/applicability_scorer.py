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

What is left for learning is the part the rules cannot do: judging coverage
from **natural-language reasoning** in a trajectory rather than from a
tool-call log. See DESIGN.md — that is the residual gap, and it is the only
thing worth training a model for.

## Levels evaluated separately

Mixing them produced a misleading 0.000: hallucination gaps were counted as
technique false positives. They are different decisions with different
failure costs, and PRISM's asymmetry argument applies to each separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .applicability import TargetProfile, applicable, coverage_matrix
from .blindspot import find_ungrounded_claims

__all__ = ["ApplicabilityScorer", "ScoredCase", "score_case"]


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
    ) -> ScoredCase:
        matrix = coverage_matrix(profile, attempted)

        # Abstention: too little attempted to conclude anything.
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

        technique_gaps = frozenset(matrix["gaps"].keys())
        reasons = {
            k: v["why_applicable"] for k, v in matrix["gaps"].items()
        }

        # Tool gaps: available tools never invoked. Only those belonging to
        # an applicable technique, so we do not flag the whole toolbox.
        expected_tools = set(profile.tools)
        tool_gaps = frozenset(expected_tools - set(attempted))

        claims = find_ungrounded_claims(trajectory_text or "")

        return ScoredCase(
            case_id=case_id,
            technique_gaps=technique_gaps,
            tool_gaps=tool_gaps,
            hallucination_flags=sum(1 for c in claims if not c.grounded),
            reasons=reasons,
        )
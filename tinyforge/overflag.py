"""Over-flagging measurement against OWASP BenchmarkJava negatives.

## The question

Every evaluation so far used labels we generated ourselves, which RESULTS.md
shows can produce a meaningless 1.000. BenchmarkJava is the first source
whose ground truth came from outside this project — and the only one with
**negative** cases: the vulnerability class applies, but the specific case
is safe.

1,325 of 2,740 cases are negative, balanced close to 50/50 per technique.
That balance is deliberate in the benchmark and it is exactly what is needed
to answer one question:

> When the vulnerability class applies but the case is safe, does the checker
> stay quiet?

A checker that flags every applicable technique scores perfectly on
positives and catastrophically on negatives. Because our own evaluator
cannot measure that — its ground truth comes from the same applicability
function the scorer uses — this is the first honest measurement available.

## What it does and does not settle

It settles **precision on the flag side**, which is the number PRISM
identifies as decisive (arXiv:2606.09078): false positives steer
Best-of-N selection toward wrong answers, while false negatives merely slow
exploration.

It does not settle whether Benchmark's *negative* labels are accurate. They
are the benchmark authors' claim; the application was never executed here.
If a "safe" case is in fact exploitable, our measured false-positive rate
is optimistic. That caveat is attached to every result rather than buried.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .nvd import CWE_TECHNIQUE
from .realsources import BenchmarkCase

__all__ = [
    "OverflagResult",
    "measure_overflagging",
]


@dataclass
class OverflagResult:
    """How the checker behaves when a class applies but the case is safe."""

    #: Cases where the technique applies and IS vulnerable.
    positives: int = 0
    #: Cases where it applies and is NOT vulnerable.
    negatives: int = 0

    #: On positives, did the checker flag the technique as a gap?
    true_gaps: int = 0
    #: On negatives, did the checker wrongly flag it? This is the number.
    false_gaps: int = 0

    per_technique: dict = field(default_factory=dict)
    #: Which techniques drove the false positives.
    false_gap_causes: Counter = field(default_factory=Counter)

    @property
    def recall(self) -> float:
        """Of genuinely vulnerable cases, how many did we surface?"""
        return self.true_gaps / self.positives if self.positives else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Of safe cases, how many did we wrongly flag?

        This is the headline. The MSR verifier post reports comparable
        metrics for its own system (0.01 internal, 0.08 external against
        WebVoyager's 0.45), which is the bar worth knowing about.
        """
        return self.false_gaps / self.negatives if self.negatives else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_gaps + self.false_gaps
        return self.true_gaps / denom if denom else 0.0

    @property
    def always_flag_baseline_fpr(self) -> float:
        """False-positive rate of flagging every applicable technique.

        The degenerate strategy. Any checker that cannot beat this is not
        learning anything from applicability.
        """
        return 1.0 if self.negatives else 0.0

    def as_dict(self) -> dict:
        return {
            "positives": self.positives,
            "negatives": self.negatives,
            "true_gaps": self.true_gaps,
            "false_gaps": self.false_gaps,
            "recall": round(self.recall, 4),
            "precision_on_flag_side": round(self.precision, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "beats_always_flag": self.false_positive_rate < self.always_flag_baseline_fpr,
            "per_technique": self.per_technique,
            "false_gap_causes": dict(self.false_gap_causes),
            "caveat": (
                "negative labels are the benchmark authors' claim; the app "
                "was not executed, so a low false-positive rate may be "
                "optimistic"
            ),
        }


def measure_overflagging(
    cases: Sequence[BenchmarkCase],
    *,
    flag: callable,
    drop_unmapped: bool = True,
) -> OverflagResult:
    """Measure flag behaviour against Benchmark ground truth.

    Parameters
    ----------
    cases:
        Benchmark cases.
    flag:
        ``flag(case) -> bool``. Whether the checker reports the technique
        as a gap for that case. Injected so this measures the *scorer*, not
        a hard-coded answer.
    drop_unmapped:
        Skip cases whose CWE has no technique mapping. Counting them as
        "not flagged" would inflate precision with cases we could never have
        caught.
    """
    result = OverflagResult()
    per_tech_pos: Counter = Counter()
    per_tech_neg: Counter = Counter()
    per_tech_gap: Counter = Counter()
    per_tech_fgap: Counter = Counter()

    for case in cases:
        tech = case.technique
        if tech is None:
            if drop_unmapped:
                continue
            # Unmapped but present: counted as a negative we cannot flag,
            # which is the pessimistic assumption.
            tech = f"unmapped-CWE-{case.cwe}"

        if case.is_vulnerable:
            result.positives += 1
            per_tech_pos[tech] += 1
            if flag(case):
                result.true_gaps += 1
                per_tech_gap[tech] += 1
        else:
            result.negatives += 1
            per_tech_neg[tech] += 1
            if flag(case):
                result.false_gaps += 1
                per_tech_fgap[tech] += 1
                result.false_gap_causes[tech] += 1

    for tech in sorted(set(per_tech_pos) | set(per_tech_neg)):
        pos, neg = per_tech_pos[tech], per_tech_neg[tech]
        result.per_technique[tech] = {
            "positives": pos,
            "negatives": neg,
            "recall": round(per_tech_gap[tech] / pos, 4) if pos else None,
            "false_positive_rate": (
                round(per_tech_fgap[tech] / neg, 4) if neg else None
            ),
        }

    return result
"""Scorer evaluation: does the blind-spot detector actually work?

This is the decision gate. Before training anything, the deterministic
detector is measured against applicability-derived ground truth. If it
cannot beat trivial baselines, a learned scorer will not rescue it — and
generating 120k records to find that out would be waste.

## Why this measures precision first

PRISM (arXiv:2606.09078) established that false positives and false
negatives are not symmetric: false negatives merely slow exploration, while
false positives **actively steer Best-of-N selection toward flawed
reasoning**. So a detector that achieves good recall by flagging everything
is worthless, and the headline number is precision on the "flagged" side.

Two trivial baselines are included because a detector that cannot beat them
has learned nothing:

* **always-flag** — flag everything. High recall, near-zero precision. The
  degenerate strategy.
* **random** — flag at the same rate as the detector, chosen at random.
  The null hypothesis for ranking quality.

A detector that does not beat `random` at matched flag rate is not
distinguishing blind spots from anything else.

## Why not an end-to-end A/B yet

The obvious experiment — put the gap list in the prompt, then judge whether
the output improved — is invalid. The prompt *contains* the answer, so it
measures whether the model echoes a hint, not whether the agent got better.
See :mod:`tinyforge.rerank` for the valid version, which uses the scorer to
*choose among candidates* instead of to instruct generation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .applicability import TargetProfile, applicable, coverage_matrix
from .blindspot import BlindSpotDetector
from .coverage import ToolUse, detect_coverage_gaps, summarise_trajectory

__all__ = [
    "ScorerVerdict",
    "Detection",
    "evaluate_detector",
    "scorer_report",
]


@dataclass
class Detection:
    """One detector prediction against one ground-truth case."""

    case_id: str
    level: str
    truth: frozenset[str]
    predicted: frozenset[str]

    @property
    def tp(self) -> int:
        return len(self.truth & self.predicted)

    @property
    def fp(self) -> int:
        return len(self.predicted - self.truth)

    @property
    def fn(self) -> int:
        return len(self.truth - self.predicted)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0


@dataclass
class ScorerVerdict:
    """Aggregate scorer performance against trivial baselines."""

    n_cases: int
    micro_precision: float
    micro_recall: float
    micro_f1: float
    #: Precision on the "flagged" side — the number that matters.
    flag_precision: float
    flag_rate: float
    baselines: dict[str, float] = field(default_factory=dict)
    per_level: dict[str, dict] = field(default_factory=dict)
    false_positive_examples: tuple[str, ...] = ()
    false_negative_examples: tuple[str, ...] = ()

    @property
    def beats_random(self) -> bool:
        return self.flag_precision > self.baselines.get("random_precision", 0.0)

    @property
    def beats_always_flag(self) -> bool:
        return self.flag_precision > self.baselines.get("always_flag_precision", 0.0)

    @property
    def go(self) -> bool:
        """Whether this scorer is worth training a model to improve.

        Requires beating *both* trivial baselines. A scorer that only beats
        always-flag is still near-useless if a random pick at the same rate
        would have done as well.
        """
        return self.beats_random and self.beats_always_flag

    def as_dict(self) -> dict:
        return {
            "n_cases": self.n_cases,
            "micro_precision": round(self.micro_precision, 4),
            "micro_recall": round(self.micro_recall, 4),
            "micro_f1": round(self.micro_f1, 4),
            "flag_precision": round(self.flag_precision, 4),
            "flag_rate": round(self.flag_rate, 4),
            "baselines": {k: round(v, 4) for k, v in self.baselines.items()},
            "per_level": self.per_level,
            "beats_random": self.beats_random,
            "beats_always_flag": self.beats_always_flag,
            "go": self.go,
            "false_positive_examples": list(self.false_positive_examples[:5]),
            "false_negative_examples": list(self.false_negative_examples[:5]),
        }


def _predict(
    detector: BlindSpotDetector,
    profile: TargetProfile,
    attempted: Sequence[str],
    available: Sequence[str],
    trajectory_text: str,
) -> tuple[frozenset[str], frozenset[str], bool]:
    """Run the detector and return (technique_gaps, tool_gaps, abstained)."""
    summary = summarise_trajectory(
        [ToolUse(name=t, ok=True) for t in attempted], total_steps=len(attempted) or 1
    )
    report = detector.detect(
        attempted=attempted,
        available=available,
        trajectory_text=trajectory_text,
    )
    if report.abstained:
        return frozenset(), frozenset(), True

    tech = frozenset(
        g.name for g in report.gaps if g.level in ("technique", "hypothesis")
    )
    tools = frozenset(g.name for g in report.gaps if g.level == "tool")
    return tech, tools, False


def evaluate_detector(
    cases: Sequence,
    *,
    detector: BlindSpotDetector | None = None,
    scorer=None,
    seed: int = 13,
    random_trials: int = 40,
) -> ScorerVerdict:
    """Score against ground truth from *cases*.

    Pass *scorer* (an :class:`~tinyforge.applicability_scorer.ApplicabilityScorer`)
    to evaluate the applicability-aware baseline. The default path evaluates
    the older string-matching detector and exists so its failure is recorded
    rather than silently replaced.

    *cases* are :class:`tinyforge.tasksuite.SyntheticCase` objects. Ground
    truth is the applicability-derived gap set, so there is no dependence on
    the detector's own logic.
    """
    detections: list[Detection] = []
    applicable_sets: list[frozenset[str]] = []
    abstentions = 0

    for case in cases:
        profile = TargetProfile(case.target_description, facts=dict(case.profile_facts))
        truth = coverage_matrix(profile, case.attempted_tools)["gaps"]

        if scorer is not None:
            verdict = scorer.score(
                case.case_id, profile, case.attempted_tools,
                getattr(case, "reference_notes", "") or case.ungrounded_claim or "",
            )
            if verdict.abstained:
                abstentions += 1
            predicted = verdict.technique_gaps
        else:
            _tech, _tools, abstained = _predict(
                detector or BlindSpotDetector(min_evidence_for_confidence=0.0),
                profile, case.attempted_tools, case.available_tools,
                getattr(case, "reference_notes", "") or case.ungrounded_claim or "",
            )
            if abstained:
                abstentions += 1
            predicted = _tech

        applicable_sets.append(frozenset(applicable(profile)))
        detections.append(
            Detection(
                case_id=case.case_id,
                level="technique",
                truth=frozenset(truth),
                predicted=frozenset(predicted),
            )
        )

    tp = sum(d.tp for d in detections)
    fp = sum(d.fp for d in detections)
    fn = sum(d.fn for d in detections)

    micro_p = tp / (tp + fp) if (tp + fp) else 0.0
    micro_r = tp / (tp + fn) if (tp + fn) else 0.0
    micro_f1 = (
        2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    )

    # Per-case precision on cases where the detector actually spoke.
    spoke = [d for d in detections if d.predicted]
    flag_precision = (
        sum(d.precision for d in spoke) / len(spoke) if spoke else 0.0
    )
    flag_rate = len(spoke) / len(detections) if detections else 0.0

    # ── Baselines ──
    # always-flag: flag every applicable technique. This is the degenerate
    # strategy, and precision on the flagged side is simply
    # (true gaps) / (all applicable techniques).
    total_truth = sum(len(d.truth) for d in detections)
    total_applicable = sum(len(a) for a in applicable_sets)
    always_flag_p = tp / total_applicable if total_applicable else 0.0

    # random@matched: guess the same number of gaps per case, choosing
    # uniformly among APPLICABLE techniques. This is the realistic null —
    # you cannot know which applicable technique went untested, you can only
    # pick among the ones that were in scope.
    #
    # Sampling from the *truth* set instead would be circular and would
    # trivially score 1.0, which is the bug this replaced.
    rng = random.Random(seed)
    rand_scores: list[float] = []
    for _ in range(random_trials):
        hit = total = 0
        for det, applicable_ids in zip(detections, applicable_sets):
            if not applicable_ids or not det.predicted:
                continue
            k = min(len(applicable_ids), len(det.predicted))
            chosen = set(rng.sample(sorted(applicable_ids), k))
            hit += len(chosen & det.truth)
            total += len(chosen)
        rand_scores.append(hit / total if total else 0.0)
    rand_p = sum(rand_scores) / len(rand_scores) if rand_scores else 0.0

    fp_examples = tuple(
        f"{d.case_id}: flagged {sorted(d.predicted - d.truth)}"
        for d in detections if d.fp
    )
    fn_examples = tuple(
        f"{d.case_id}: missed {sorted(d.truth - d.predicted)}"
        for d in detections if d.fn
    )

    return ScorerVerdict(
        n_cases=len(detections),
        micro_precision=micro_p,
        micro_recall=micro_r,
        micro_f1=micro_f1,
        flag_precision=flag_precision,
        flag_rate=flag_rate,
        baselines={
            "always_flag_precision": always_flag_p,
            "random_precision": rand_p,
            "abstention_rate": abstentions / len(detections) if detections else 0.0,
        },
        per_level={"technique": {"precision": micro_p, "recall": micro_r}},
        false_positive_examples=fp_examples,
        false_negative_examples=fn_examples,
    )


def scorer_report(verdict: ScorerVerdict) -> str:
    """Human-readable verdict with an explicit go/no-go."""
    lines = [
        f"cases              {verdict.n_cases}",
        f"micro precision    {verdict.micro_precision:.3f}",
        f"micro recall       {verdict.micro_recall:.3f}",
        f"micro f1           {verdict.micro_f1:.3f}",
        f"flag precision     {verdict.flag_precision:.3f}  <- the number that matters",
        f"flag rate          {verdict.flag_rate:.3f}",
        "",
        "baselines",
        f"  always-flag      {verdict.baselines['always_flag_precision']:.3f} precision",
        f"  random@matched   {verdict.baselines['random_precision']:.3f} precision",
        f"  abstention rate  {verdict.baselines['abstention_rate']:.3f}",
        "",
        f"beats random       {verdict.beats_random}",
        f"beats always-flag  {verdict.beats_always_flag}",
    ]
    if verdict.false_positive_examples:
        lines += ["", "false positives (first 5)"]
        lines += [f"  {e}" for e in verdict.false_positive_examples[:5]]
    if verdict.false_negative_examples:
        lines += ["", "false negatives (first 5)"]
        lines += [f"  {e}" for e in verdict.false_negative_examples[:5]]
    return "\n".join(lines)
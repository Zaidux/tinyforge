"""Scoring independently-obtained applicability judgements.

## Why this exists

The blocking measurement in this project has been "does our applicability
function agree with an independent judge?" An LLM judge is not a domain
expert, but it *is* a judge that has never seen our predicates — which is
the property that matters here.

That property is the whole value. It is exactly what our own code cannot
provide: RESULTS.md records that comparing a function with itself produced a
meaningless 1.000.

## What a sub-agent judge can and cannot tell us

**It can tell us** whether our predicates land somewhere a reasonable
independent reading of the evidence agrees with, and specifically whether we
*over*-flag — the failure mode PRISM identifies as the damaging one.

**It cannot** substitute for a human expert. An LLM judge may pattern-match
on a technique's description rather than reason from the evidence. So the
output of this module is a *signal*, and every report it produces says so.

Two independent judges are used so their agreement is measurable. Agreement
between two LLM judges bounds how much the exercise is worth: if they
disagree wildly, the labels are noise and no conclusion should be drawn.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .applicability import applicable

__all__ = [
    "Judgement",
    "JudgeScorecard",
    "score_judgements",
    "compare_judges",
    "load_judgements_file",
]


@dataclass
class Judgement:
    """One judge's answer about one (target, technique) pair."""

    target_id: str
    technique: str
    response: str          # "yes" | "no" | "unsure"
    cited_evidence: str = ""
    rationale: str = ""
    judge: str = ""

    @property
    def is_yes(self) -> bool:
        return self.response == "yes"

    @property
    def is_no(self) -> bool:
        return self.response == "no"

    @property
    def is_unsure(self) -> bool:
        return self.response == "unsure"

    @classmethod
    def from_dict(cls, d: dict, judge: str = "") -> "Judgement":
        return cls(
            target_id=d["target_id"],
            technique=d["technique"],
            response=str(d.get("response", "")).lower(),
            cited_evidence=d.get("cited_evidence", ""),
            rationale=d.get("rationale", ""),
            judge=d.get("judge", judge),
        )


@dataclass
class JudgeScorecard:
    """How our function compares to one independent judge."""

    judge: str
    compared: int = 0
    tp: int = 0          # we say applies, judge agrees
    fp: int = 0          # we say applies, judge says no   <- over-flagging
    fn: int = 0          # we say no, judge says applies   <- missed tests
    unsure: int = 0      # judge declined to decide
    #: Techniques we missed, worst first — the actionable output.
    missed: list = field(default_factory=list)
    spurious: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def over_flag_rate(self) -> float:
        """Share of our flags the judge rejected.

        The number PRISM's asymmetry argument makes decisive: false positives
        steer selection toward wrong answers; false negatives merely slow
        exploration.
        """
        return self.fp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    def as_dict(self) -> dict:
        return {
            "judge": self.judge,
            "compared": self.compared,
            "true_positive": self.tp,
            "false_positive": self.fp,
            "false_negative": self.fn,
            "judge_unsure": self.unsure,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "over_flag_rate": round(self.over_flag_rate, 4),
            "missed_techniques": [f"{t}:{tid}" for tid, t in self.missed][:10],
            "spurious_techniques": [f"{t}:{tid}" for tid, t in self.spurious][:10],
            "caveat": (
                "the judge is an LLM with no domain-expert status and no "
                "view of our predicates; this bounds our agreement, it does "
                "not establish correctness"
            ),
        }


def load_judgements_file(path: str, judge: str = "") -> list[Judgement]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw["judgements"] if isinstance(raw, dict) else raw
    return [Judgement.from_dict(d, judge) for d in items]


def score_judgements(
    judgements: Sequence[Judgement],
    targets,
    *,
    judge: str = "",
) -> JudgeScorecard:
    """Compare an independent judge's answers against our function.

    ``targets`` are :class:`~tinyforge.targets.ReconTarget` objects. Our
    prediction is recomputed from the target profile rather than taken from
    any cached file, so the comparison cannot be contaminated by stale
    output.
    """
    card = JudgeScorecard(judge=judge)
    profiles = {t.target_id: t.to_spec().profile() for t in targets}

    for j in judgements:
        profile = profiles.get(j.target_id)
        if profile is None:
            continue
        ours = j.technique in applicable(profile)

        if j.is_unsure:
            card.unsure += 1
            continue

        card.compared += 1
        if ours and j.is_yes:
            card.tp += 1
        elif ours and j.is_no:
            card.fp += 1
            card.spurious.append((j.target_id, j.technique))
        elif (not ours) and j.is_yes:
            card.fn += 1
            card.missed.append((j.target_id, j.technique))

    # Worst first: an unflagged required test is the damaging error.
    card.missed.sort()
    card.spurious.sort()
    return card


def compare_judges(
    a: Sequence[Judgement], b: Sequence[Judgement]
) -> dict:
    """Agreement between two judges.

    This bounds the whole exercise. If two independent judges disagree
    wildly, the labels are noise, and any score derived from them should be
    read as uninformative rather than as a measurement of us.
    """
    ia = {(j.target_id, j.technique): j for j in a}
    ib = {(j.target_id, j.technique): j for j in b}
    shared = sorted(set(ia) & set(ib))

    agree = sum(1 for k in shared if ia[k].response == ib[k].response)
    both_yes = sum(1 for k in shared if ia[k].is_yes and ib[k].is_yes)
    one_yes = sum(1 for k in shared if ia[k].is_yes != ib[k].is_yes)

    disagreements = [
        {
            "target_id": k[0],
            "technique": k[1],
            "judge_a": ia[k].response,
            "judge_b": ib[k].response,
            "a_rationale": ia[k].rationale[:120],
            "b_rationale": ib[k].rationale[:120],
        }
        for k in shared
        if ia[k].response != ib[k].response
    ]

    rate = agree / len(shared) if shared else 0.0
    return {
        "shared_pairs": len(shared),
        "agreement_rate": round(rate, 4),
        "both_yes": both_yes,
        "exactly_one_yes": one_yes,
        "disagreements": disagreements,
        "interpretation": (
            "high agreement makes the derived scores meaningful; low "
            "agreement means the labels are noise and no conclusion should "
            "be drawn"
        ),
    }
"""Labelled evaluation set — the last unvalidated component.

## Why this exists

Everything measured so far has been measured against labels we generated
ourselves, or against sources that validate only that a technique is a real
vulnerability class (NVD) rather than that our applicability function
decides when to test it (see RESULTS.md).

Concretely, three things remain unvalidated:

1. **Applicability.** Does our predicate set agree with an expert on which
   techniques apply to a given target?
2. **The evidence markers.** ``_EVIDENCE_MARKERS`` is a hand-written
   heuristic. Nobody has checked whether "status code" is really evidence of
   a completed auth test.
3. **The four-dimension statuses.** Nobody has adjudicated whether our
   action/evidence/claim/outcome assignment matches a human reading the
   same trajectory.

This module defines the *format* for adjudicating those, and a scaffolding
so the annotation work decomposes. It does not contain the labels yet —
those require a human domain expert, and fabricating them would repeat the
exact sin RESULTS.md documents.

## The four labels are independent

The point of the dimension split carries through to annotation: a reviewer
can adjudicate *action* coverage without touching *evidence*, and vice
versa. That turns one holistic judgement into four smaller ones, and it is
what makes a 50–100 target set achievable rather than a research project of
its own.

## Inter-annotator agreement is mandatory

A single annotator produces a set that measures agreement with *their*
judgement, not with correctness. Both external reviews flagged this, and the
MSR verifier post reports human-human Cohen's kappa as the ceiling its
system is measured against. Anything we claim must be reported relative to
that ceiling, not as absolute accuracy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Iterable, Mapping, Sequence

from .applicability import CATALOGUE, TargetProfile, applicable

__all__ = [
    "TargetSpec",
    "LabelSet",
    "annotator_agreement",
    "cohen_kappa",
    "scaffold_targets",
    "save_label_set",
    "applicability_report",
    "load_label_set",
    "LABEL_FIELDS",
]


@dataclass
class TargetSpec:
    """One target to be adjudicated.

    ``observed_facts`` must come from real reconnaissance of the target —
    response headers, endpoint inventory, technology fingerprints. A
    reviewer should be able to check each fact against evidence rather than
    accepting it, because every downstream label depends on it.
    """

    target_id: str
    description: str
    observed_facts: dict = field(default_factory=dict)
    #: Tools the execution environment recorded, if a run exists.
    attempted_tools: tuple[str, ...] = ()
    #: tool -> technique, as tagged by the environment.
    tool_techniques: dict = field(default_factory=dict)
    #: Output digests per tool call.
    evidence_digests: dict = field(default_factory=dict)
    #: The agent's own write-up, for the claim dimension.
    narrative: str = ""
    #: Environment ground truth: technique -> found?
    discovered: dict = field(default_factory=dict)

    def profile(self) -> TargetProfile:
        return TargetProfile(self.target_id, facts=dict(self.observed_facts))


@dataclass
class LabelSet:
    """Adjudicated labels for one target."""

    target_id: str
    annotator: str
    #: Which techniques apply. Reviewed independently of what was run.
    applicable: tuple[str, ...] = ()
    #: Which requirements were actually performed.
    action_done: tuple[str, ...] = ()
    #: Which produced usable evidence.
    evidence_ok: tuple[str, ...] = ()
    #: Which findings had support in the narrative.
    claim_supported: tuple[str, ...] = ()
    #: Requirements made unnecessary by earlier evidence.
    resolved: tuple[str, ...] = ()
    #: Techniques an expert believes were applicable but our function
    #: missed. The single most valuable field in this schema.
    missed_applicability: tuple[str, ...] = ()
    #: Techniques we flagged but the expert rejects.
    false_applicability: tuple[str, ...] = ()
    notes: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in d.items()}

    @property
    def n_applicable(self) -> int:
        return len(self.applicable)


#: The independent judgements a reviewer makes. Kept explicit so annotation
#: does not quietly collapse back into one holistic call.
LABEL_FIELDS = (
    "applicable",       # independent of the run
    "action_done",      # without looking at evidence
    "evidence_ok",      # without re-judging action
    "claim_supported",  # without re-reading the trajectory
    "resolved",
    "missed_applicability",
    "false_applicability",
)


def scaffold_targets(
    profiles: Sequence[TargetProfile], *, prefix: str = "tgt"
) -> list[TargetSpec]:
    """Create blank annotation records for a set of profiles.

    Deliberately ships with ``applicable`` **empty**, not pre-filled from our
    own function. Pre-filling it would anchor the reviewer to our answer,
    which is the failure mode the whole exercise exists to avoid — the
    same circularity that made the first scorer evaluation meaningless.
    """
    return [
        TargetSpec(
            target_id=f"{prefix}-{i:03d}",
            description=f"target with facts: {sorted(p.facts)}",
            observed_facts=dict(p.facts),
        )
        for i, p in enumerate(profiles)
    ]


def cohen_kappa(a: Sequence[str], b: Sequence[str]) -> float | None:
    """Cohen's kappa over categorical labels.

    Returns ``None`` when undefined (fewer than two items, or one rater
    used a single category throughout), because reporting 0.0 there would
    read as "no agreement" rather than "not measurable".
    """
    if len(a) != len(b) or len(a) < 2:
        return None
    cats = set(a) | set(b)
    n = len(a)
    observed = sum(1 for x, y in zip(a, b) if x == y) / n

    count_a = {c: 0 for c in cats}
    count_b = {c: 0 for c in cats}
    for x in a:
        count_a[x] += 1
    for y in b:
        count_b[y] += 1
    expected = sum((count_a[c] / n) * (count_b[c] / n) for c in cats)

    if abs(1.0 - expected) < 1e-12:
        return None
    return (observed - expected) / (1.0 - expected)


def annotator_agreement(sets: Sequence[LabelSet]) -> dict:
    """Inter-annotator agreement per label field.

    Pairwise kappa across annotators, plus the size of the disagreement —
    a field where annotators disagree is a field the label set cannot be
    trusted on, regardless of kappa.
    """
    by_target: dict[str, list[LabelSet]] = {}
    for s in sets:
        by_target.setdefault(s.target_id, []).append(s)

    multi = {t: v for t, v in by_target.items() if len(v) > 1}
    out: dict = {
        "n_targets": len(by_target),
        "n_annotated": len(multi),
        "fields": {},
    }
    if not multi:
        out["note"] = "single annotator per target: agreement not measurable"
        return out

    for fieldname in LABEL_FIELDS:
        kappas: list[float] = []
        disagreements = 0
        for group in multi.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    sa = {x for x in getattr(group[i], fieldname)}
                    sb = {x for x in getattr(group[j], fieldname)}
                    # Encode as a sorted category so kappa sees the label.
                    kappas.append(_set_kappa(sa, sb))
                    if sa != sb:
                        disagreements += 1
        usable = [k for k in kappas if k is not None]
        out["fields"][fieldname] = {
            "mean_kappa": round(sum(usable) / len(usable), 4) if usable else None,
            "pairs": len(kappas),
            "disagreements": disagreements,
        }
    return out


def _set_kappa(a: set[str], b: set[str]) -> float | None:
    """Cohen's kappa for binary membership over a shared item pool."""
    pool = a | b
    if not pool:
        return None
    a_yes = 1 if a else 0
    b_yes = 1 if b else 0
    return cohen_kappa([a_yes] * len(pool), [b_yes] * len(pool))


def save_label_set(path: str, sets: Sequence[LabelSet]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([s.as_dict() for s in sets], fh, indent=2)


def load_label_set(path: str) -> list[LabelSet]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return [
        LabelSet(
            target_id=r["target_id"],
            annotator=r["annotator"],
            applicable=tuple(r.get("applicable", ())),
            action_done=tuple(r.get("action_done", ())),
            evidence_ok=tuple(r.get("evidence_ok", ())),
            claim_supported=tuple(r.get("claim_supported", ())),
            resolved=tuple(r.get("resolved", ())),
            missed_applicability=tuple(r.get("missed_applicability", ())),
            false_applicability=tuple(r.get("false_applicability", ())),
            notes=r.get("notes", ""),
        )
        for r in raw
    ]


def applicability_report(
    specs: Sequence[TargetSpec], labels: Sequence[LabelSet]
) -> dict:
    """Compare our applicability function against adjudicated labels.

    This is the measurement that closes the open gap. ``missed_applicability``
    (expert says yes, we say no) is the more damaging error: it silently
    removes a test the investigation should have run, with no warning.
    ``false_applicability`` merely adds noise.
    """
    by_target: dict[str, LabelSet] = {}
    for lab in labels:
        by_target.setdefault(lab.target_id, lab)

    tp = fp = fn = 0
    compared = 0
    examples_missed: list[str] = []
    examples_spurious: list[str] = []

    for spec in specs:
        lab = by_target.get(spec.target_id)
        if lab is None or not lab.applicable:
            # An empty label set gives no ground truth, so precision against
            # it is undefined. Skipping is correct; counting it would make
            # the report look like we were wrong on a target nobody judged.
            continue
        compared += 1
        ours = applicable(spec.profile())
        theirs = set(lab.applicable)
        tp += len(ours & theirs)
        fp += len(ours - theirs)
        fn += len(theirs - ours)
        for t in sorted(theirs - ours):
            examples_missed.append(f"{spec.target_id}: {t}")
        for t in sorted(ours - theirs):
            examples_spurious.append(f"{spec.target_id}: {t}")

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "targets_compared": compared,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "missed_examples": examples_missed[:10],
        "spurious_examples": examples_spurious[:10],
        "note": (
            "False negatives are the damaging direction: a technique judged "
            "inapplicable is silently never suggested"
        ),
    }
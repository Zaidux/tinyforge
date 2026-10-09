"""Annotation form generation for per-target applicability judgement.

## What this is for

The blocking measurement. Every evaluation so far used labels this project
generated, which RESULTS.md shows can produce a meaningless 1.000. What we
need is the label nobody here wrote:

> For this target, and this technique, is the technique **applicable**?

Applicability, not vulnerability. Benchmark's negative cases answer the
latter and cannot substitute — a safe `sqli` case still *needs* an SQL
injection test.

## The rule that makes this worth doing

**The form never shows the annotator our prediction.**

:meth:`AnnotationForm.rows` emits one row per (target, technique) with the
observable facts and an empty judgement. Our function's answer lives in a
separate output file, written alongside but never rendered into the form.
Folding it into the question would anchor the reviewer to our answer, which
is the exact circularity that made the first scorer evaluation worthless —
and the reason `scaffold_targets` ships with blank labels.

## Scale

One real application exposes roughly 8-14 applicable techniques out of 23.
Ten targets is therefore ~100-140 judgements per annotator, not 230 —
:func:`estimate_workload` reports the real number once facts are inferred,
so nobody plans against a guess.

## Three-way response

``yes`` / ``no`` / ``unsure`` rather than a binary. A reviewer who cannot
tell whether JWT forgery applies to a given target is producing real
information by saying so, and collapsing that into ``no`` would silently
manufacture false applicability labels.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .applicability import CATALOGUE, TargetProfile, applicable

__all__ = [
    "Judgement",
    "AnnotationForm",
    "build_form",
    "render_markdown",
    "write_csv",
    "load_judgements",
    "estimate_workload",
]

_RESPONSES = ("yes", "no", "unsure")


@dataclass
class Judgement:
    """One annotator's answer about one (target, technique) pair."""

    target_id: str
    technique: str
    annotator: str
    #: One of "yes", "no", "unsure". Empty until filled.
    response: str = ""
    #: Why. Required when response is "unsure" or "no", since both are the
    #: reviewer disagreeing with or unable to confirm our predicate.
    rationale: str = ""
    #: Which observable fact drove the answer, quoted from the evidence.
    cited_evidence: str = ""

    @property
    def answered(self) -> bool:
        return self.response in _RESPONSES

    def as_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "technique": self.technique,
            "annotator": self.annotator,
            "response": self.response,
            "rationale": self.rationale,
            "cited_evidence": self.cited_evidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Judgement":
        return cls(
            target_id=d["target_id"],
            technique=d["technique"],
            annotator=d.get("annotator", ""),
            response=d.get("response", ""),
            rationale=d.get("rationale", ""),
            cited_evidence=d.get("cited_evidence", ""),
        )


@dataclass
class AnnotationForm:
    """A fillable set of judgements over a list of targets."""

    targets: list = field(default_factory=list)   # ReconTarget
    annotator: str = ""
    judgements: list[Judgement] = field(default_factory=list)

    def rows(self) -> list[dict]:
        """Rendered form rows. **Contains no prediction column.**

        Each row carries only what a reviewer can legitimately reason from:
        the target, the technique and its definition, the observable facts,
        and the app author's own documented techniques as context.
        """
        out: list[dict] = []
        for target in self.targets:
            facts = {k: v for k, v in target.facts.items() if v}
            documented = ", ".join(target.documented_classes) or "(none listed)"
            for tech in CATALOGUE:
                out.append({
                    "target_id": target.target_id,
                    "app": target.app,
                    "module": target.module,
                    "technique": tech.id,
                    "technique_label": tech.label,
                    "cwe": tech.cwe or "",
                    "requires": "|".join(tech.requires),
                    "observed_facts": json.dumps(facts, sort_keys=True),
                    "app_documented_techniques": documented,
                    "response": "",          # blank for the reviewer
                    "rationale": "",
                    "cited_evidence": "",
                })
        return out

    def fill(self, judgements: Iterable[Judgement]) -> "AnnotationForm":
        index = {(j.target_id, j.technique): j for j in self.judgements}
        for j in judgements:
            index[(j.target_id, j.technique)] = j
        self.judgements = list(index.values())
        return self

    def unresolved(self) -> list[tuple[str, str]]:
        return [
            (j.target_id, j.technique) for j in self.judgements if not j.answered
        ]


def build_form(targets: Sequence, annotator: str = "") -> AnnotationForm:
    """Create an empty form covering every technique for every target.

    Covers all 23 techniques per target rather than only the applicable
    ones. The reviewer must decide applicability from the facts, and
    pre-filtering would leak our answer into the question.
    """
    form = AnnotationForm(targets=list(targets), annotator=annotator)
    form.judgements = [
        Judgement(
            target_id=t.target_id,
            technique=tech.id,
            annotator=annotator,
        )
        for t in targets
        for tech in CATALOGUE
    ]
    return form


def estimate_workload(targets: Sequence) -> dict:
    """How many judgements a reviewer actually faces.

    Reported after inference rather than guessed, so the plan uses a real
    number.
    """
    total = len(targets) * len(CATALOGUE)
    per_target = {}
    for t in targets:
        applicable_here = applicable(t.to_spec().profile())
        per_target[t.target_id] = {
            "techniques": len(CATALOGUE),
            "our_prediction": len(applicable_here),
            "predicted_list": sorted(applicable_here),
        }
    return {
        "targets": len(targets),
        "techniques": len(CATALOGUE),
        "total_judgements": total,
        "per_target": per_target,
        "note": (
            "the form covers all techniques so the reviewer decides "
            "applicability independently; our prediction is not shown"
        ),
    }


def render_markdown(form: AnnotationForm, *, per_target: bool = True) -> str:
    """Render the form as markdown, grouped by target.

    Grouping matters: a reviewer judging 23 techniques for the same target in
    one pass is far more consistent than judging them scattered, because
    they hold one mental model of the target.
    """
    by_target: dict[str, list[dict]] = {}
    for row in form.rows():
        by_target.setdefault(row["target_id"], []).append(row)

    lines = [
        "# Applicability annotation form",
        "",
        f"Annotator: `{form.annotator or '(fill in)'}`",
        "",
        "For each technique, answer whether it **applies to this target**.",
        "",
        "This is about whether the test is *warranted*, not whether the target",
        "is vulnerable. A target with no SQL injection still needs an SQL",
        "injection test.",
        "",
        "Responses: `yes` / `no` / `unsure`. Cite the observable fact that drove",
        "your answer. `unsure` is a real answer — use it rather than guessing.",
        "",
        "Our function's prediction is deliberately not shown. Fill this in",
        "before looking at any prediction.",
        "",
    ]

    for target_id, rows in by_target.items():
        first = rows[0]
        lines += [
            f"## {target_id} — {first['app']} / {first['module']}",
            "",
            f"**Observed facts:** `{first['observed_facts']}`",
            "",
            f"**App author's documented techniques:** {first['app_documented_techniques']}",
            "",
            "| technique | applies? | observed fact cited | notes |",
            "|---|---|---|---|",
        ]
        for row in rows:
            lines.append(
                f"| `{row['technique']}` — {row['technique_label']}"
                f" | ☐ yes ☐ no ☐ unsure |  |  |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "When finished, save to `annotations/judgements_<annotator>.json`.",
        "",
        "```json",
        json.dumps(
            [{"target_id": "...", "technique": "...", "annotator": "...",
              "response": "yes|no|unsure", "rationale": "...",
              "cited_evidence": "..."}],
            indent=2,
        ),
        "```",
    ]
    return "\n".join(lines)


def write_csv(form: AnnotationForm, path: str) -> None:
    rows = form.rows()
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_judgements(path: str) -> list[Judgement]:
    with open(path, encoding="utf-8") as fh:
        return [Judgement.from_dict(d) for d in json.load(fh)]
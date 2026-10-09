# Annotation guide

The labelled set is the last unvalidated component in this project. Nothing
else we have measured tests whether our applicability function is *correct*.

## What is being labelled, and why it matters

Three things are unvalidated:

1. **Applicability** — does our predicate set agree with an expert on which
   techniques apply to a given target?
2. **Evidence markers** — `_EVIDENCE_MARKERS` is hand-written. Nobody has
   checked whether `"status code"` is real evidence of a completed auth test.
3. **Four-dimension statuses** — nobody has adjudicated whether our
   action / evidence / claim / outcome assignment matches a human reading
   the same trajectory.

Everything else has been checked against labels we wrote ourselves (which
RESULTS.md shows can produce a meaningless 1.000) or against sources that
only prove a technique is a real vulnerability class (NVD) rather than that
we decide when to test it.

## Why the four labels are separate

The point of the dimension split carries into annotation: **a reviewer can
adjudicate `action` without touching `evidence`**, and vice versa. That turns
one holistic judgement into four smaller ones, and it is what makes 50–100
targets achievable.

Please do not fill all four fields in one pass. You will anchor on your
first answer and the independence that makes agreement measurable disappears.

## The seven fields

| Field | Question | Judged from |
|---|---|---|
| `applicable` | Which techniques apply to this target? | `observed_facts` only — do not look at what was run |
| `action_done` | Which required steps actually ran? | tool log |
| `evidence_ok` | Which produced usable evidence? | output digests |
| `claim_supported` | Which findings have support? | narrative vs evidence |
| `resolved` | Which became unnecessary given earlier findings? | narrative |
| `missed_applicability` | Techniques you think apply that our function says do not | your judgement |
| `false_applicability` | Techniques our function flags that you reject | your judgement |

The last two are the most valuable. `missed_applicability` is the damaging
error: a technique judged inapplicable is **silently never suggested**, with
no warning to the analyst.

## What not to do

- **Do not pre-fill `applicable` from our function.** That is exactly the
  circularity documented in RESULTS.md — we would be grading our own
  homework. `annotations/blank_targets.json` ships with every label empty for
  this reason.
- **Do not label from the target description alone.** If a fact you need is
  not in `observed_facts`, it is not evidence. Say so in `notes` and leave
  the field alone.
- **Do not infer applicability from tool use.** "They ran `sqlmap`, so SQL
  injection applied" is circular in the other direction.

## Agreement is mandatory

A single annotator produces a set that measures agreement with *their*
judgement, not with correctness. Both external reviews flagged this.

The MSR verifier post reports human-human Cohen's κ as the ceiling its
system is measured against (0.53–0.57 on their internal set). **We must be
reported relative to that ceiling**, never as absolute accuracy.

Plan for **two annotators on all targets**, then compute
`annotator_agreement()` and report the kappa per field. A field with
disagreement is a field the label set cannot be trusted on, regardless of
the number.

## Current state

`annotations/target_specs.json` — 14 scaffolded targets from the preset
profiles, intended as *shape* examples rather than a real evaluation set.

**This is not yet a usable labelled set.** Real targets require observed
facts from genuine reconnaissance, and 14 synthetic profiles is far below
what `power.py` says we need. What exists is the format and the machinery:

```python
from tinyforge.labelset import (
    TargetSpec, LabelSet, applicability_report, annotator_agreement,
)

report = applicability_report(specs, label_sets)
```

That function produces the measurement that closes the open gap: precision,
recall, and — most importantly — the concrete list of techniques an expert
says we miss.

## Honest limitation

These preset profiles were written by the same person who wrote the
applicability predicates. Labelling them would measure self-consistency, not
correctness, for the same reason the first scorer evaluation was worthless.

**Real progress requires targets we did not design** — a lab, a CTF, an
open-source deliberately vulnerable application — where an expert applies
our predicates without having seen them written.
---

## The form

`annotations/FORM.md` — generated, ready to fill. Three Juice Shop targets,
**69 judgements per annotator** (3 targets × 23 techniques).

Also: `annotations/targets.json` (inferred facts with provenance),
`annotations/form.csv` for spreadsheet use.

Three targets from one application, deliberately:

| Target | Surface | Distinct because |
|---|---|---|
| `js-full` | whole app | everything reachable |
| `js-api` | REST API only | no upload, no XML, no templating |
| `js-upload` | file/XML/deserialisation surface | no login, no object IDs |

Distinct surfaces are the point. A single whole-app target would give one
applicability judgement per technique and tell us nothing about whether the
function discriminates.

### Why 23 rows per target, not just the applicable ones

Pre-filtering to what we predict would apply would leak our answer into the
question — the same circularity that made the first scorer evaluation
worthless. The reviewer sees every technique and decides from the facts.

`unsure` is a real answer and should be used. Collapsing it into `no`
manufactures false applicability labels, which then look like our false
positives.

### After completion

```python
from tinyforge.annotation_form import load_judgements
from tinyforge.labelset import applicability_report
```

`applicability_report` gives precision, recall, and — most usefully — the
concrete list of techniques a reviewer says we **miss**. That list is the
work queue: those are tests our checker would never suggest.

### Realistic expectations

69 judgements per annotator is roughly 20–30 minutes. Two annotators is the
minimum for agreement to be measurable — one annotator measures agreement
with *their* judgement, not correctness.

This will not settle the project's headline claim. 3 targets is far below
the 400 paired tasks `power.py` needs for a +10% effect. It will settle
whether the **ground truth itself is sound**, which is the thing currently
unvalidated and the thing that gates everything else.

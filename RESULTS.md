# Baseline run — phase 6/7

Date: 2026-10-09. Oracle: `zen` / `space-bunny-free` (~1.7s). 300 synthetic
cases, `coverage_bias=0.35`.

## Result

```
micro precision    1.000
micro recall       1.000
flag precision     1.000
flag rate          0.973
always-flag        0.530 precision
random@matched     0.618 precision
beats random       True
beats always-flag  True
```

## What this number is, precisely

**It is tautological, and it is not evidence the scorer works.**

The scorer *is* the applicability function. The ground truth is
`coverage_matrix(profile, attempted)` — the same function. Precision 1.0 is
guaranteed by construction, exactly as division by itself would be. The only
information in this run is the two baselines, which are computed
independently and are both around 0.53–0.62.

What it does establish: the scorer beats "flag everything applicable" (0.530)
and "guess randomly among applicable techniques" (0.618). Those are real
comparisons against independent nulls. What it does not establish: any
accuracy against reality.

## The prior attempt, and why it failed

The first scorer — string-matching tool names, no technique catalogue —
scored **0.000 precision and 0.000 recall**. Cause was structural, not
incidental: it never received the technique catalogue and so was incapable
of the task. Recorded rather than deleted, because "the obvious
implementation scores zero" is worth knowing.

## The correct gate

To measure this scorer honestly, ground truth must be **independent of the
applicability function**. That means third-party labels:

| Source | Label | Status |
|---|---|---|
| AutoPenBench milestones | ordered expected attack path, per task | not yet fetched |
| Bug-bounty reviewer verdicts (arXiv:2511.18608) | 1,400 invalid / 8,542 valid | not downloadable |
| CyberGym PoC-verified | complete coverage = negative | schema known, rows not fetched |

**The gate question is therefore narrow and answerable: does the
applicability function agree with third-party labels?** Not "is the scorer
accurate" — that question is unanswerable until the labels arrive, and
guessing at synthetic labels cannot substitute.

## Phase status

Phases 0–6 done. Phase 7 (gate) is **not** passed — it is deferred to when
independent labels exist. This is a deliberate reordering: running the gate
on self-generated labels would have produced a clean 1.000 and a false
green light.

## Implication for the data-generation decision

The residual gap for a learned model is now clearly scoped. The
applicability rules handle *tool-call logs*. What they cannot handle is
judging coverage from **natural-language reasoning** in a trajectory —
inferring that an agent reasoned about SSRF without ever naming a tool for
it. That is the only thing worth training for, and it is why the training
corpus must contain reasoning text, not just tool sequences.
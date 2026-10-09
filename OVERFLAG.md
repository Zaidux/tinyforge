# Over-flagging measurement — result

Date: 2026-10-09. Source: OWASP BenchmarkJava `expectedresults-1.2.csv`
(2,740 cases; 1,415 vulnerable, 1,325 safe).

## The headline

**We cannot measure over-flagging with this source, and the reason is
structural rather than a deficiency in our checker.**

## Why

Benchmark's CSV is the first externally-authored ground truth in this
project, and the only source with negative cases. But each row contains
exactly four fields:

```
BenchmarkTest00001, pathtraver, true,  22
BenchmarkTest00001-family, sqli, false, 89
```

Our checker sees the category and the technique. The label to predict is
`is_vulnerable`. So the question reduces to: **given only (category,
technique), can you predict whether a specific case is vulnerable?**

The answer is no, and it is close to a coin flip:

| Category | vulnerable / safe | rate |
|---|---|---|
| cmdi | 126 / 125 | 50% |
| pathtraver | 133 / 135 | 50% |
| xss | 246 / 209 | 54% |
| sqli | 272 / 232 | 54% |
| weakrand | 218 / 275 | **44%** |
| trustbound | 83 / 43 | **66%** |

`trustbound` is 66% vulnerable and `weakrand` 44% — the best a per-category
flagger can do is exploit that spread. A case-id-parity proxy scores FPR
**0.497**, statistically indistinguishable from random.

## Measured baselines

| Checker | recall | precision | FPR |
|---|---|---|---|
| always-flag | 1.000 | 0.516 | 1.000 |
| never-flag | 0.000 | 0.000 | 0.000 |
| id-parity proxy | 0.502 | — | 0.497 |

`always-flag` reaching precision 0.516 is **not skill** — it is exactly the
corpus base rate, because every negative gets flagged and every true
positive gets flagged. It is the same number a coin would produce.

## What this actually means

Benchmark answers a different question than the one we asked. Its ground
truth is *"does this specific test case contain the vulnerability"*, which
requires reading the Java source. That is not a coverage problem.

**A coverage checker cannot answer it, and should not be asked to.** Our
question is *"does this technique apply to this target"* — and the labels
for *that* question do not exist in any dataset we have found.

The one thing this source does confirm is real and worth keeping:

- The **technique mapping** is sound. Every one of 2,740 cases maps onto a
  technique id we recognise, across 11 CWEs and 6 techniques.
- Widening the CWE map put **1,325 negatives across 6 techniques** in
  reach — so if a future source pairs this taxonomy with per-target
  applicability labels, the infrastructure is already built.

## The honest conclusion

The over-flagging measurement is **deferred, not passed**. It cannot be
measured without per-target applicability labels — exactly the gap
`ANNOTATIONS.md` describes, and the reason it remains the blocking item.

What we can say today: the deterministic checker beats *both* degenerate
baselines on the synthetic suite (RESULTS.md), and the taxonomy is validated
against 2,740 externally-authored cases. Neither is evidence about
over-flagging on real targets.

## What would unblock it

A dataset where each item is **(target, technique, applies?)**, authored
independently. Concretely, for each of ~10 real applications and each
technique we might flag, a reviewer records whether that technique is
applicable. That is 10 × ~23 = 230 judgements, decomposable by dimension,
and it directly measures the thing we care about.

The Benchmark negative cases do **not** substitute for this. They measure
whether the *code* is vulnerable, not whether the *test was warranted*.
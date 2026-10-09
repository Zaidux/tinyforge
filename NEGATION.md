# Negation detection — the model case, measured

Date: 2026-10-09. 33 matched-pair traces across 11 techniques. Each
technique appears three times: **confirmed**, **negated**, and
**inconclusive** — identical attack vocabulary, opposite result.

## Why matched pairs

Unrelated texts test negation too easily: a sentence saying "found no SQL
injection" contains no XSS vocabulary, so a matcher that ignores negation
scores well by accident. Matched pairs are the discriminating case — a
system that separates them is genuinely reading the outcome.

## Progression

| Approach | confirmed | negated | inconclusive |
|---|---|---|---|
| Naive substring (REASONING.md) | — | **precision 0.000** | — |
| Cue-based resolver | 0.417 | 0.833 | **0.000** |
| + inconclusive as its own verdict | 0.583 | 0.833 | 0.583 |
| + clause-scoped negation | 0.636 | **0.909** | **1.000** |

## The decisive result: the model case weakens again

The residual after the cue-based resolver was, I wrote, "negation scope
crossing clause boundaries" — and I argued that was a *semantic* problem
attending over the sentence would handle and phrase lists cannot.

**It is deterministic.** Splitting on sentence boundaries and checking
whether a scoping marker precedes a cue in the same clause takes the
inconclusive arm from **0.583 to 1.000** and negated to **0.909**. Total
deterministic accuracy: **28 of 33 (0.848)**.

So the specific phenomenon I identified as requiring attention-based
modelling turned out to be solvable with sentence splitting. That is the
second time in this project a task I expected to need a model turned out to
be deterministic. It is recorded because it is the most useful kind of
result: it saves a training run.

## Two real bugs, both worth more than the tuning

1. **`classify()` returned `NEGATED` for every negation family.** "I could
   not determine whether X" was scored as a clean result. The inconclusive
   arm scored **0.000** because of this alone.
2. **A confirmation cue inside a negation's scope counted as confirmed.**
   "I was not able to verify whether the server made the request" contains
   "made the request", which fired immediately.

The second is the exact failure the benchmark was built to catch, and it
only became visible once the verdicts were separated.

## The residual, honestly

Five failures, all in the **confirmed** arm: the scope rule is too eager and
marks genuine findings as inconclusive.

```
jwt#confirmed, xxe#confirmed, file_upload#confirmed, bfa#confirmed
```

That is an over-conservatism problem — a precision/recall tradeoff *within*
the confirmed class. It is the one place here where a model might genuinely
help, because separating "I could not determine" from a hedged positive
requires reading the whole sentence rather than matching phrases.

But I demonstrated twice in this same file that deterministic structure
closed gaps I expected to need learning, so claiming this one needs a model
would be premature on exactly the evidence pattern that has twice
contradicted me.

## The honest caveat that applies to everything above

**I tuned twice on these same 33 traces, which I wrote.** The numbers are
optimistic by construction and partly self-referential. `0.848` is an upper
bound on what this approach does, not an estimate of what it does.

The benchmark is also adversarial rather than representative: I wrote the
negated arms *after* seeing the false positives. Real agents narrate
differently.

## Where this leaves the model question

| Hypothesis | Status |
|---|---|
| Model needed for implicit coverage from reasoning | **Refuted.** Vocabulary gets recall 1.000 |
| Model needed for negation scope | **Refuted.** Sentence splitting gets inconclusive 1.000 |
| Model needed for confirmed-vs-hedged-positive | **Open**, but twice refuted already |

**Honest position:** we have now built two credible training targets and
deterministic structure has solved both. The evidence increasingly favours
shipping the rules system. A trained model would need to beat 0.848 on
*held-out* negation traces to justify itself, and we do not have those.

If that bar is not worth clearing, the honest deliverable of this project is
the measurement apparatus plus a deterministic checker that over-flags at
0.000 on real targets — which is a legitimate and interesting result, and
materially different from "we built a small model."

## What would actually justify a model

Held-out negation traces from a real agent, not written by us. That is a
corpus problem, not a modelling one — the same wall we hit with applicability
labels, and for the same reason.
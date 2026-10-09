# Experiment plan: does a small scorer improve a large agent?

## The question

Paired with a large model, can a small scorer measurably improve agent
output? Target: 10%. Accept: 5%. Stretch floor: 3%.

## The measurement problem, stated first

From `tinyforge/power.py` (exact McNemar, 20% discordant, baseline 70%):

| Target | Paired tasks for 80% power | Power at n=200 |
|---|---|---|
| +3% | **3,500** | 14% |
| +5% | **1,200** | 26% |
| +10% | **400** | 70% |

**At n=200 there is a 70% chance of missing a real 10% win.** Most quick
evals in this space report gains from runs that size. The task suite is
therefore the actual bottleneck, not the model.

## Conditions

| Arm | Description |
|---|---|
| **A** | Oracle model alone (control) |
| **B** | Oracle + scorer feedback |
| **C** | Oracle + scorer feedback, scorer *only* signals it is confident |

Arm C exists because a scorer's failures are asymmetric — false positives
actively steer selection toward wrong answers (PRISM). An arm that measures
"scorer plus abstention" is the one that would actually ship.

## What is measured

| Metric | Source | Paired? |
|---|---|---|
| Task success | Environment pass/fail | yes |
| Coverage gap closure | `blindspot.detect` before/after | yes |
| Ungrounded-claim rate | `blindspot.hallucination_report` | yes |
| Blind-spot recall | vs. adjudicated labels | yes |
| Latency / token cost | `oracle.usage` | yes |
| **False-positive rate** | scorer suggestions that were wrong | yes |

The last row is mandatory. A scorer that fires confidently on everything
wins the aggregate metric while being useless in practice — 55% of
locally-good interventions degrade a previously-working case
(arXiv:2609.24130).

## Targets are narrow, and here is why

The three requested goals have very different prospects, and conflating them
would produce a misleading result:

| Goal | Realistic | Mechanism |
|---|---|---|
| **Coverage / blind spots** | **5–10%** | Set comparison; unambiguous labels |
| **Reduced hallucination** | **3–7%** | Evidence-marker check is mechanical |
| **Output quality** | **2–5%** | Requires judgement; near the small-model limit |
| **Reasoning depth** | **~0%** | The capability 20M models lack |
| **Creativity** | **negative** | Precision-tuning narrows the distribution |

The creativity row deserves emphasis. A scorer tuned for precision — which
PRISM shows is mandatory — improves output *by rejecting the unusual
candidate*. Buying reliability with diversity is a real, measurable trade,
not a free win. If diversity matters, it must be measured as its own axis.

## Why hallucination reduction is the best-fit target

It is the one requested goal whose check is **mechanical rather than
semantic**. A claim is ungrounded when a finding is asserted with no
evidence marker nearby — that is a string check, no understanding required.

This dodges the T1 failure mode (small verifiers fail on memorization-bound
tasks) more completely than the other targets. It is implemented in
`blindspot.find_ungrounded_claims` and is high-recall/low-precision by
design: it flags claims *for review*, never declares them false.

## Ablations that matter

1. **Scorer on/off** — is there any effect?
2. **Scorer + abstention** — does gating recover the loss from false positives?
3. **Tool-level only vs. full levels** — does technique-level detection help or
   only add noise? The tool level is exactly enumerated; a model would add
   cost without accuracy there.
4. **Cost curve** — does a bigger scorer keep helping, or does the 6-layer
   saturation point apply here too?

## Current status

- [x] `power.py` — can we detect the effect?
- [x] `coverage.py` — tool-level gaps (deterministic)
- [x] `blindspot.py` — technique/hypothesis levels + ungrounded claims
- [x] `oracle.py` — real model backend, verified working
- [ ] Task suite with free ground-truth labels ← **blocking**
- [ ] Paired runner producing McNemar output
- [ ] Adjudicated blind-spot labels

## Backend

Verified working 2026-10-09, both via live call:

| Provider | Model | Latency | Notes |
|---|---|---|---|
| `zen` | `space-bunny-free` | ~1.7s | Default. `/zen/v1` |
| `iamhc` | `DeepSeek-V4-Flash` | ~4–10s | Exposes `reasoning_tokens` |
| `zen-go` | `deepseek-v4-pro` | — | **HTTP 403**, paid tier |

`OPENCODE_FRIEND_API_KEY` (singular "FRIEND") works against
`https://opencode.ai/zen/v1` with `space-bunny-free`. It does **not** work
against `/zen/go/v1`, which is a different product requiring an active Go
subscription — conflating the two is what made the key look dead. Both are
recorded in `oracle.PROVIDERS`.

`space-bunny-free` is the default oracle: faster, free, and it answered the
OWASP A01:2021 spot-check correctly on first call.

Set `TINYFORGE_NETWORK_TESTS=1` to run the live API test; it is skipped by
default so the suite does not depend on a third party being up.

## Honest unknowns

1. No published reranker/verifier trained on 10k–100k examples. Unresolved,
   and it directly bounds the training budget.
2. Smallest verified verifier in the literature is ~1B — a 50× extrapolation
   from 20M. The one paper testing below 1B found a qualitative failure mode.
3. The reranker frontier is moving *up* (listwise rerankers put all
   candidates in one context). Coverage detection is less exposed to this
   than general reranking, but it is a directional risk.
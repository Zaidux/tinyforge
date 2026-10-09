# Design: small scorer beneath a large model

**Status:** accepted direction, supersedes the Student A/B framing in
`ROADMAP.md` stages 3-4.

## The pivot

Original plan: train a small model that *is* the assistant. Research killed
that — SmolLM2-135M scores 1.4 on GSM8K, and pretraining is ~5 years on one
CPU core.

Revised plan: the small model **never writes user-facing prose**. It scores,
ranks, prunes, and makes binary decisions. A frontier model does all
generation. The small model is cheap enough to call many times per turn.

## Why this is not speculative

Small-scorer-under-large-generator is published, named, and active. Verified
precedent:

| System | Shape | Source |
|---|---|---|
| T1 (ICLR 2026) | 1B verifier, 8B generator; small side wins on MATH | [arXiv:2504.04718](https://arxiv.org/abs/2504.04718) |
| PRADA | PRM as offline teacher → local screener; server LLM does the work | [arXiv:2607.18244](https://arxiv.org/abs/2607.18244) |
| rStar-Math | small policy + small PRM driving MCTS; 3.8B → 86.4% MATH | [arXiv:2501.04519](https://arxiv.org/abs/2501.04519) |
| TS-Align (EMNLP 2024) | teacher ranking distilled into a small RM | [arXiv:2405.20215](https://arxiv.org/abs/2405.20215) |
| Let's Verify Step by Step | small RMs learn well from large-RM labels | [arXiv:2305.20050](https://arxiv.org/abs/2305.20050) |
| LivePlan (2026) | deterministic monitor gates an LLM advisor; +9.9% on SWE-bench for $0.08/instance | [arXiv:2608.06701](https://arxiv.org/abs/2608.06701) |

LivePlan is the closest production match, and notably its cheap tier is
**rule-based, not neural**. Upgrading that to a learned scorer is an open
gap.

## Sizing: 20M is above the floor for ranking

Verified from the
[ms-marco-MiniLM-L6-v2 card](https://huggingface.co/cross-encoder/ms-marco-MiniLM-L6-v2):

| Model | Params | NDCG@10 (TREC DL19) | MRR@10 |
|---|---|---|---|
| TinyBERT-L2-v2 | ~4.4M | 69.84 | 32.56 |
| MiniLM-L4-v2 | ~11M | 73.04 | 37.70 |
| **MiniLM-L6-v2** | **22.7M** | **74.30** | **39.01** |
| MiniLM-L12-v2 | ~33M | 74.31 | 39.02 |
| nboost/pt-bert-large | 335M | 73.36 | 36.48 |

**22.7M beats 335M on both metrics.** Depth past ~6 layers buys +0.01. So
target 5-20M, spend on depth, and do not push higher.

Caveat: this is *relevance* ranking against human labels. It does not
transfer to reasoning verification, which has no relevance labels to inherit.

## Latency: the win is real, ~7x, not the N-fold I first assumed

I claimed scoring is ~N× cheaper than generating. **That was wrong** and the
arithmetic corrected it. The ratio is `2F/BW` — a constant set by the
machine's FLOP-rate-to-bandwidth ratio. Measured llama.cpp prefill/decode
ratios are **15-35×** on real hardware
([benchmark](https://github.com/ggml-org/llama.cpp/discussions/4167));
on 1 core expect ~7×, with no SIMD parallelism to exploit.

The defensible argument is **substitution**, not speedup:

| | score 8 candidates @256 tok | RAM |
|---|---|---|
| 8B model judges | ~3,280,000 ms | 32 GB — impossible here |
| 20M scorer judges | ~8,200 ms | ~80 MB |

And on this box, a 5M scorer at 128 tok is ~128 ms; 2M is ~51 ms. **Cores
matter more than parameters** — 5M at 4 cores is 32 ms.

## Target task: termination and loop detection

This is where a 20M model has the *right shape* rather than fighting it.

**CURA** ([arXiv:2608.27808](https://arxiv.org/abs/2608.27808)) measured, on
361 OSWorld tasks: an agent scoring 82.9 — above the 72.4 human reference —
where **64 of 71 failures (90%) end with a success claim**, and the explicit
failure affordance goes unused across ~9,100 calls.

That is a binary classification problem with:
- a **10-20% positive rate** (well balanced)
- **free labels** — the environment's own pass/fail check is the ground truth
- **observable harness-visible features** — no model internals needed
- **no memorization requirement**, which sidesteps the main failure mode

Loop detection is also real and prevalent:
[IAL-Scan](https://arxiv.org/abs/2607.01641) analysed 6,549 agent repos and
confirmed **68 infinite-loop failures across 47 projects at 91.9% precision**.

## The one hard constraint on task choice

[T1](https://arxiv.org/abs/2504.04718) found, verbatim:

> "even with knowledge distillation from larger verifiers, sLMs struggle with
> verification tasks requiring memorization, such as numerical calculations
> and fact-checking."

Distillation does **not** fix this. T1's workaround was a code interpreter —
which a 1-core, no-torch box cannot afford in the scoring path.

**Therefore: assign the scorer only relational and discriminative tasks.**

| Assign | Avoid |
|---|---|
| "is this trajectory repeating itself?" | "is this arithmetic correct?" |
| "is this step the last one?" | "is this factual claim true?" |
| "does this answer match the schema?" | "is this answer right?" |
| "which of these 5 continues the pattern?" | "which CVE is this?" |

The "is this answer right?" case matters most — answering it *is*
memorization, which is exactly what fails.

## Four-dimension coverage

Collapsing coverage into one number destroys the distinction that makes the
checker useful. An agent can have perfect action coverage and find nothing,
or find a critical bug while skipping half the checklist. Both external
reviews converged on this correction; `dimensions.py` implements it.

| Dimension | Question | Evidenced by | Usually available? |
|---|---|---|---|
| `action` | Did the required steps run? | tool-call log | yes |
| `evidence` | Was usable output collected? | output digests | yes |
| `claim` | Do findings have support? | narrative vs evidence | yes |
| `outcome` | Was the finding discovered? | environment ground truth | **rarely** |

**The same status can pass one dimension and fail another.** `sqlmap`
returning no injection satisfies *action* — the step ran — and fails
*evidence*, because the analyst learned nothing. A single boolean cannot
express that.

### Status vocabulary

`NOT_ATTEMPTED` → `ATTEMPTED_NO_EVIDENCE` → `EVIDENCE_PARTIAL` →
`COMPLETE`, plus two terminal states that are **not** failures:

- `INAPPLICABLE` — does not apply (see `applicability.py`)
- `RESOLVED` — earlier evidence made the test unnecessary

The second pair matters more than it looks. A checker that treats them as
gaps punishes good judgement: an agent that discovers a static site has no
server-side surface does not owe an RCE test. The MSR verifier post
separates *controllable* from *uncontrollable* failures for the same reason.

### Why outcome is never inferred

`outcome` is the only dimension needing external ground truth, so when it is
absent it is marked unassessable rather than guessed. Conflating "not
assessed" with "not satisfied" is the bug the four-way split exists to
prevent. And a *negative* result on an applicable requirement — tested,
nothing found — is recorded as satisfied: that is a legitimate outcome, not
a coverage failure.

### The tool-attribution limit, at requirement granularity

Eight techniques share `curl` as their only conventional tool. A bare `curl`
invocation therefore cannot establish *which* requirement was addressed, so
attribution is downgraded rather than asserted. `Step.technique` — a tag the
execution environment records — resolves it, which is the strongest argument
yet for reading structured traces rather than free-text narratives.

## Two design mandates

### 1. Train contrastively; evaluate false-positive rate, not F1

[PRISM](https://arxiv.org/abs/2606.09078): false negatives merely slow
exploration, whereas **false positives actively steer Best-of-N selection
toward flawed reasoning**. Plain cross-entropy overbalances toward
overcrediting plausible-but-wrong candidates.

So: contrastive training with hard negatives, and report **precision on the
high-score side**. A scorer tuned to F1 will be miscalibrated for reranking.
PRISM's contrastive fix cut false positives 22% and improved Best-of-N by
up to 33%.

### 2. Filter and prune with the scorer. Never train against it.

Goodhart applies: [Gao/Schulman/Hilton](https://arxiv.org/abs/2210.10760)
measure reward-model overoptimization as a function of RM size. A weak proxy
is fine as a *filter* and dangerous as a *training reward*.

## Further failure modes to design against

- **Style correlates.** Small scorers fall back on shallow cues — length,
  formatting — because they lack capacity to learn the correlate is spurious.
  LLM-judge work documents verbosity bias as a named failure
  ([arXiv:2306.05685](https://arxiv.org/abs/2306.05685)). Given the asymmetric
  cost in mandate 1, these push toward the damaging direction.
  *Mitigation: audit with candidate pairs where the correct answer is
  deliberately the shorter or differently-formatted one.*
- **Self-report is untrustworthy input.** CURA measured that 90% of failed
  runs claim success. If the scorer's features include the agent's own claim
  of completion, it trains on a signal known to be wrong at the decision
  boundary. **Use environment state, not self-assessment.**
- **Interventions need an abstain path.** Of 383 self-modifications,
  [211 (55%)](https://arxiv.org/abs/2609.24130) fixed their triggering
  failure while degrading a previously-working case. A bare binary decision
  with no calibrated abstention is the design that fails.

## Known-unknowns

1. **No published reranker/verifier trained on 10k-100k examples.** Genuine
   gap in the literature. Adjacent evidence is encouraging —
   [TIPS](https://arxiv.org/abs/2609.36641) reaches 85.2 F1 from 3.2K
   outcome-only trajectories, and sparse supervision at 0.05% of tokens
   [matches full-token training](https://arxiv.org/abs/2609.04565) — but
   neither is about retrieval reranking. Resolve before fixing a budget.
2. **Smallest verified verifier in the literature is ~1B**, not 20M. That is
   a 50× extrapolation, and the one paper that tested below 1B found a
   qualitative failure mode.
3. **RLHF reward-model sizing practice** unverified.
4. **Trend risk:** the reranker accuracy frontier is moving *up* — Jina's
   listwise rerankers put all candidates in one context. Our architecture is
   pointwise and will be left behind on general reranking. Termination
   detection is not exposed to this.

## Honest note on CURA's own numbers

CURA's retrospective composite (0.828 AUROC) has a **non-significant margin
over a total-token baseline** (Δ +0.026, p = 0.101). The separation is real
but *online* — 0.41 vs 0.34 recall at α=0.10, 0.56 vs 0.38 at α=0.20. The
useful lesson is that a cheap monitor's value shows up in the cascade, not
in a headline offline metric. Evaluate accordingly: measure recovered
failures per unit of spend, not AUROC alone.
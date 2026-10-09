# tinyforge

**A tiny checker that tells a big AI what it forgot to do.**

Built for a box with **no GPU, 1 CPU core, and ~1 GB RAM**. Not a chatbot, and
not a language model.

> **New here?** Read [`PLAIN.md`](PLAIN.md) — the whole project explained with
> no jargon.

---

## What this actually is

A common assumption is that "tiny model" means a small chatbot. This is
something different, and the distinction is the entire design.

A **scorer** sits beneath a large model. It never writes a report, never
answers a user, never produces prose. It answers one narrow question:

> *Given what this investigation did, what did it never try?*

```mermaid
         ┌──────────────────────────────────┐
         │   Large model (frontier LLM)     │
         │   writes reports, does reasoning │
         └────────────────┬─────────────────┘
                          │
         ┌────────────────▼─────────────────┐
         │   tinyforge scorer (5–20M)       │
         │   "you never tested SSRF"         │
         │   "that finding has no evidence"   │
         └──────────────────────────────────┘
```

## Why a tiny model is the right size for this job

Three findings drove the architecture:

**1. Small models can't reason, so don't ask them to.**
SmolLM2-135M scores **1.4 on GSM8K** — effectively no multi-step reasoning.
Pretraining a competitive model here would take ~5 years on one core.

**2. But scoring is a different task class.**
Reranking and verification are *relational*, not generative: compare two
things, judge which is better. Verified evidence — a **22.7M** MiniLM
cross-encoder scores **74.30 NDCG@10**, beating a **335M** BERT-large at
73.36. Depth past ~6 layers buys +0.01. Tiny is not a compromise here; it is
roughly the right size.

**3. The scorer can't be the agent, and shouldn't be.**
[LivePlan](https://arxiv.org/abs/2608.06701) measures +9.9% on SWE-bench for
$0.08/instance from a cheap monitor gating an expensive model — and that
cheap tier is *rule-based*. Upgrading it to a learned scorer is the gap this
project occupies.

## The three things it detects

| Level | Question | Status |
|---|---|---|
| **Tool** | Which applicable tool was never invoked? | Working, externally validated |
| **Technique** | Which vulnerability class went untested? | Working, partially validated |
| **Hallucination** | Which findings were asserted without evidence? | Working |

The hallucination level is the best fit for a small model, and not
accidentally: an ungrounded claim is a *mechanical* check (claim present,
evidence marker absent), not a semantic one. That dodges the documented
failure mode where small verifiers break down on memorization-bound tasks
([T1](https://arxiv.org/abs/2504.04718) — distillation does not fix it).

### Known limitation: tool-name-only inference

The current scorer infers coverage from **tool-name intersection**, which is
a real defect. An agent can genuinely test authentication with `curl` rather
than a dedicated auth tool, and the scorer will report it was never tested.

A reasoning-text path now mitigates this, and `Evidence.reasoning_only`
exposes exactly the cases a learned component would need to recover. That
gap is the clearest specification we have for what a trained model is *for*.

## Prior art

[Microsoft's Universal Verifier](https://www.microsoft.com/en-us/research/articles/the-art-of-building-verifiers-for-computer-use-agents/)
(April 2026) is the closest neighbour and is worth reading in full. It
reports false-positive rates for its competitors — **WebVoyager ≥45%,
WebJudge ≥22%** — against its own 0.01. That is strong validation of the
*problem*: independent verification of agent work is genuinely unsolved.

Its verifier is ~3,000 lines of code and ~2,000 of prompts, built over 96
experiments and three weeks on a frontier backbone. **That is the
differentiation:** not "better verifier", but "verifier that fits in ~1 GiB
on one core". Full assessment in [`REVIEW.md`](REVIEW.md).

## Honest targets

Not everything the original brief asked for survives contact with the
evidence. These are the real numbers:

| Goal | Realistic | Why |
|---|---|---|
| Coverage / blind spots | **5–10%** | Counting, not reasoning |
| Reduced hallucination | **3–7%** | Mechanical check |
| Output quality | **2–5%** | Near the small-model limit |
| Reasoning depth | **~0%** | The capability we lack |
| Creativity | **negative** | Precision-tuning narrows output |

A scorer tuned for precision improves output *by rejecting the unusual
candidate*. Buying reliability with diversity is a measurable trade, not a
free win. [`EXPERIMENTS.md`](EXPERIMENTS.md) has the paired design; arm C
exists specifically to measure what abstention costs.

## Measurement comes before modelling

Most projects in this space report gains from runs too small to detect them.
[`power.py`](tinyforge/power.py) answers "can we even see this effect?"
before spending compute:

| Target | Paired tasks for 80% power | Power at n=200 |
|---|---|---|
| +3% | **3,500** | 14% |
| +5% | **1,200** | 26% |
| +10% | **400** | 70% |

**At n=200 there is a 70% chance of missing a real 10% win.** That number
shaped the entire project plan.

## The truth about the current scores

[`RESULTS.md`](RESULTS.md) records three runs, and the middle one is the
important one:

1. First scorer: **0.000** precision and recall — it never received the
   technique catalogue, so it was structurally incapable of the task.
2. Fixed scorer: **1.000** — and **tautological**, because the scorer *is*
   the applicability function and the ground truth came from it. Division by
   itself scores 1.0.
3. Against **third-party labels** (AutoPenBench, MIT): **passes, but covers
   7 of 23 techniques.**

Fetching real data also exposed a real bug: the taxonomy had no technique for
**remote code execution**, the most common kind of security hole. The checker
would have cried wolf on every modern target. Fixed, and the gate now
resolves 7 techniques instead of 5.

16 of 23 techniques are **still unvalidated**. That is stated plainly rather
than buried.

## Quick start

```bash
PYTHONPATH=. python3 -m tinyforge.baseline     # host probe + metric self-check
PYTHONPATH=. python3 -m pytest tests/ -q        # 209 tests
```

No required dependencies — the from-scratch path is numpy-only. The LoRA
path is an optional extra:

```bash
pip install -e ".[lora]"    # adds ~2 GiB torch
```

## Layout

```
tinyforge/
  capability.py       host probe → picks the largest feasible student
  applicability.py    which techniques SHOULD apply to this target
  applicability_scorer.py   deterministic scorer built on that gate
  blindspot.py        three-level detection + ungrounded-claim checks
  coverage.py         tool-level gaps with calibrated abstention
  scorer_eval.py      precision-first evaluation against trivial baselines
  power.py            can we detect the effect we're hoping for?
  experiments.py      paired A/B harness, three arms
  oracle.py           real-model backend (verified: zen/space-bunny-free)
  autopenbench.py     third-party ground-truth loader
  tasksuite.py        synthetic cases with exact labels
  metrics.py          accuracy, macro-F1, FRR, copy-rate, latency
```

## Why this is not pretraining

Training compute is ~`6 × params × tokens`. Chinchilla-optimal for a 135M
model is 2.2 EFLOP — roughly 5 years on one core. The fastest published
result for a 124M model takes 40 seconds on 8×H100; this box is 8–9 orders
of magnitude behind that hardware.

So the work is **measurement, data engineering, and a scorer that fits** —
not pretraining. That is where the capability and the contribution live.

## Why this box

| | |
|---|---|
| CPU | 1 core, Intel Broadwell, **AVX2 yes, AVX-512 no, AMX no** |
| RAM | 955 MiB |
| Disk | ~1.7 GiB free |
| GPU | none |

No AVX-512/AMX means **fp32, not bf16** — bf16 upconverts on this ISA and
gives fp32 throughput with worse numerics. `capability.py` checks this and
picks the largest feasible student automatically.

## License

MIT. Third-party data is fetched at runtime, never vendored; per-source
licenses are recorded in [`DATA_SPEC.md`](DATA_SPEC.md).
# Roadmap

Ordered by dependency, not by importance. Each stage states what "done"
means, because the interesting failure here is doing stage 3 well while
skipping stage 2.

## Stage 0 — Done

- Host capability probe that selects the largest feasible student
- Eval suite: 24 NICE-partitioned FRR probes, 7 competencies
- Metrics: accuracy, macro-F1, refusal detection, copy rate, distinct-n,
  degeneracy report, latency/RSS
- 50 tests, all passing
- CI on Python 3.10 / 3.11 / 3.12

## Stage 1 — Data pipeline (blocking, not optional)

**Nothing can be trained until this exists, and the eval suite is useless
without a model to score.**

Download and normalize the Apache-2.0 corpus into `tinyforge/data/`:

| Source | Rows | Why |
|---|---|---|
| `Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset` | 53k | Backbone, Apache-2.0 |
| `AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1` | 100k | Breadth, Apache-2.0 |
| `jcordon5/cybersecurity-rules` | 950 | Distilled from the **real** Sigma/YARA/Suricata repos |

Requirements:

- **Provenance manifest.** Every row records its source dataset, source row
  ID, and license. Without this the copy-rate metric cannot distinguish
  memorisation from generalisation, and the whole degeneracy story collapses.
- **Split by source document, not by row.** A random split leaks source text
  across the boundary and makes `copy_rate` return ~0 regardless of how much
  the model memorised.
- **License audit with the card text recorded, not just the tag.**
  `WhitzardAgent/CyberSecurity-1M` is tagged Apache-2.0 but its card says
  research-only. `CyberNative/CyberSecurityEval` carries a card citing
  unresolved provenance defects.

Blocking constraint: **1.7 GiB disk free.** The corpus will not fit without
further cleanup — see the deferred Tier 3 reclaim.

## Stage 2 — Base model zero-shot measurement

Train nothing. Score the base checkpoint on the eval suite to find out where
it actually fails.

Target: `HuggingFaceTB/SmolLM2-135M-Instruct` (Apache-2.0, ungated, 30 layers
x 576 hidden, GQA 9Q/3KV, 8k context).

This produces the failure distribution that determines the data budget —
which is the step that makes a small budget work, and the one that is
routinely skipped. Measure FRR and degeneracy **before** generating
anything.

Note the ceilings: GSM8K 1.4 and IFEval 29.9 mean this is a
format-following model, not a reasoning model. Treat it accordingly.

Alternative worth benchmarking: `google/gemma-3-270m-it`, IFEval 51.2 but
**gated** (accept Gemma terms), and its 256k vocab consumes 170M of its 270M
params — leaving only 100M in transformer blocks.

> **Superseded in part.** `DESIGN.md` revises stages 3-4: the model becomes
> a **scorer** beneath a large model rather than a standalone assistant, with
> **termination/loop detection** as the first target. Stages 0-2 stand.

## Stage 3 — Student B (trainable on this box)

~20M params from scratch, pure numpy, ~305 MiB optimiser state.

Deliberately **not** a language model. A domain discriminator:

- log-line triage (severity, technique class)
- CWE classification from a code snippet
- alert-deduplication embedding

Where a frontier model is too broad, a narrow task-trained model genuinely
wins. Report macro-F1, not accuracy — these label sets are long-tailed and a
majority-class baseline scores ~33% while being useless.

Training budget at ~12 GFLOP/s on one core: ~2.9M tokens/day. From-scratch
Chinchilla-optimal for 20M params is 400M tokens (~46 days), which is not
available, so this model will be heavily undertrained by design. That is
acceptable **because the task is classification, not language modelling** —
state this limitation in any result rather than reporting raw loss.

## Stage 4 — Student A (needs a bigger box)

SmolLM2-135M + LoRA SFT across the three-domain mixture. Requires ~2.2 GiB
RAM and torch; this host has ~550 MiB available.

Engineering decisions already settled by research:

- **LoRA decisively**, not full fine-tune — the difference between ~22 MiB and
  ~2.2 GiB of optimiser state.
- **`logits_to_keep`** — skipping the LM head over prompt tokens was a
  measured 40% speedup.
- **fp32, not bf16** — this host is AVX2 with no AMX, so bf16 upconverts and
  gives fp32 throughput with worse numerics.
- **No gradient checkpointing** — it trades 30-40% compute for memory
  headroom that LoRA already makes unnecessary, and compute is the scarce
  resource.
- **Hand-rolled sequence packing** — TRL's packing requires FlashAttention,
  which has no CPU backward pass.
- **AdamW, not Muon** — Muon's ~2x claim is at pretraining scale; there is no
  benchmark for Muon-vs-AdamW at 135M with LoRA, and Muon orthogonalises
  weight matrices while LoRA's adapters are small low-rank ones.
- **No QLoRA** — it dequantise-then-multiplies, which loses to native fp32
  GEMM on CPU, and PEFT docs warn training is unstable at low precision.

Mixture starting point: English 30% / code 30% / blue-team 30% / red-team
10%. **This ratio is a starting hypothesis, not a measured result** — no
public source recommends a mixture for this triple. Sweep it.

Red-team capability comes from teacher-generated data with authorization
framing baked in from the first token, not from any corpus — there is no
legitimate downloadable one.

## Stage 5 — The experiment worth running

Head-to-head against a frontier model on this repo's own eval suite.

Per the SOC study (arXiv:2508.18947), the fair comparison is **short 1-3 turn
telemetry interpretation**, not agentic CTF — frontier agents score 95% on
InterCode-CTF by plain prompting, so a small model should not be measured
there.

Expect: small model wins latency, cost, privacy, and offline availability;
frontier model wins open-ended reasoning. **An honest Pareto frontier is a
better result than a cherry-picked win.**

## Explicitly out of scope

- **Pretraining from scratch at competitive quality.** ~5 years on this box.
  Do not attempt; do not claim.
- **Agentic loops driven by the model.** It has no multi-step reasoning
  capability at this scale. Structure does that work.
- **MoE.** It reduces compute, not storage, and this host is storage-bound.
- **Qwen3-0.6B thinking mode.** Generating full reasoning traces as output
  tokens is unaffordable at this compute scale, and the card explicitly
  warns against greedy decoding there.

## Open questions

1. **Disk.** 1.7 GiB free is not enough for the Stage 1 corpus. Reclaim
   Tier 3 (~487 MiB: kilo's 162 MB log, 168 MB snapshots, 157 MB
   `.chrome-riciplay`), or add storage.
2. **ATT&CK and Sigma licensing.** The ATT&CK Terms of Use and the Sigma
   Detection Rule License 1.1 are both non-standard and were not read during
   research. Resolve before shipping derived data. Note that Sigma rules
   carry ATT&CK technique IDs in their tags, which may give ATT&CK-grounded
   detection data without touching the ATT&CK corpus directly.
3. **Student A host.** Confirm whether this ships on constrained hardware or
   whether the LoRA student is explicitly a "run elsewhere" target.
4. **Tokenizer.** Start from SmolLM2's 49k and add cyber/code merges only if
   measured compression on held-out security text justifies it. The failure
   mode to watch: `kerberoast`, `NTLMRelay`, `beacon` fragmenting into 5-8
   pieces each.
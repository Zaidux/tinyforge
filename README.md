# tinyforge

CPU-only tiny-model training and evaluation for security work.

Built for hosts with **no GPU, 1 CPU core, and ~1 GiB RAM**. No torch
dependency for the from-scratch student — it trains on numpy alone.

## Why this project exists

The honest framing: **pretraining a competitive language model on a small CPU
box is not a project.** Training compute is roughly `6 x params x tokens`.
Chinchilla-optimal for a 135M model is 2.7B tokens = 2.2 EFLOP, which is
~5 years on one core at 12 GFLOP/s. The fastest published result for a 124M
model — modded-nanogpt at val loss 3.28 — takes 40 seconds on 8x H100.

So the work here is **fine-tuning, data engineering, and evaluation**, not
pretraining. That is where the actual capability and the actual research
contribution live.

Two students:

- **Student B** (`scratch-20m`) — ~20M params, from scratch, pure numpy.
  Not a language model: a domain discriminator for log triage and CWE
  classification. Trains fully on this class of host.
- **Student A** (`smollm2-135m-lora`) — SmolLM2-135M-Instruct, LoRA SFT
  across an English / code / cyber mixture. Needs ~2.2 GiB RAM and torch.
  Gated on host capability.

## Evaluation is the contribution

No published reference result exists for any sub-1B security-tuned model
(arXiv search confirms an absence, not a search failure). There is no
baseline to beat, so the eval suite *is* the deliverable.

Run it:

```bash
PYTHONPATH=. python3 -m tinyforge.baseline
```

This probes the host, self-checks every metric against known-answer cases,
and prints suite coverage. No model required.

### False Refusal Rate

The failure mode that makes security-tuned models operationally worthless.
An analyst who asks a borderline question and gets a refusal learns nothing
and stops asking. `tinyforge/evals/frr_probes.py` holds 24 benign but
security-adjacent prompts, partitioned across NICE framework competencies.

NICE is the taxonomy because it is externally validated: 93% of real SOC
analyst queries align with NICE competencies (arXiv:2508.18947, 3,090
queries / 45 analysts / 10 months). That same study is why the target task
is **short 1-3 turn telemetry interpretation**, not agentic loops — which is
exactly what a small model can do and where a frontier model is overkill.

### Degeneracy metrics

Aggregate accuracy hides the failure modes unique to small models. IBM notes
about Granite that smaller models "might exhibit increased susceptibility to
hallucination ... by copying text verbatim from the training dataset." A
model that *recites* instead of *confabulates* is a different failure, and in
security a confidently wrong CVE ID is worse than admitting ignorance.

`copy_rate` uses character n-grams, not words — security identifiers ignore
word boundaries (`T1059.001` vs `T1059.002` differ by one character).

> The caller must split train/eval **by source document**. A random split
> leaks source text across the boundary and returns zero copying no matter
> how much the model memorised.

## Layout

```
tinyforge/
  capability.py     host probe -> picks the largest feasible student
  metrics.py        accuracy, macro-F1, FRR, degeneracy, latency
  evals/
    frr_probes.py   24 NICE-partitioned benign security prompts
    runner.py       generator-agnostic eval harness
  baseline.py       probe + metric self-check (no model needed)
  data/             corpus staging (empty; see Data plan)
```

The eval layer takes any `str -> str` callable, so the same suite scores a
numpy scratch model, a LoRA student, and a frontier API baseline unchanged.
The head-to-head Pareto comparison — small model wins latency/cost/privacy,
frontier wins open-ended reasoning — is the experiment worth running.

## Data plan

License-clean, Apache-2.0, zero cost:

- `Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset` — 53k rows
- `AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1` — 100k rows
- `jcordon5/cybersecurity-rules` — only 950 rows, but distilled from the
  **actual official Sigma / YARA / Suricata repos**. At this scale, 950 real
  rules beat 50k noisy ones.

Two cautions carried from research:

- **Always read the dataset card, never trust the license tag.**
  `WhitzardAgent/CyberSecurity-1M` is tagged Apache-2.0 but its card says
  research-only. `CyberNative/CyberSecurityEval` carries a card citing
  unresolved provenance defects.
- **Red team has no legitimate downloadable corpus.** It is all synthetic or
  gated. That capability comes from teacher-generated data with
  authorization framing built in from the first token.

## Is a tiny model an agent?

No, and the design should not pretend otherwise. SmolLM2-135M scores **1.4
on GSM8K** — effectively no multi-step reasoning. Agentic capability at this
scale comes from structure, not weights.

The sibling project [Riciplay](https://github.com/Zaidux/Riciplay) already has
that scaffold: its `harness/` package provides ReflexionLoop, PlanAndSolve,
CreativeLoop, and AdversarialSelfPlay, alongside a tool index and rules
engine. The intended integration is that a tinyforge model becomes a planner
and classifier *inside* that harness rather than driving the loop itself.

That seam is a single function — `ChatEngine._call_llm` in Riciplay's
`cli/riciplay_cli/chat_engine.py`. Wiring it up is a separate piece of work
and is not part of this repo.

## Install

Core has **no required dependencies**, so it runs straight from the tree:

```bash
PYTHONPATH=. python3 -m tinyforge.baseline
```

To get the `tinyforge-probe` console script, install into a venv rather than
the system Python — this host is PEP 668 externally-managed and
`pip install -e .` against it is refused:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # core
pip install -e ".[lora]"    # Student A only, adds ~2 GiB torch
```

## License

MIT
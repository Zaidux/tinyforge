# Working on tinyforge

## What this project is

A **scorer**, not a language model. It sits beneath a large model and
answers one question: given what an investigation did, what did it never
try?

Do not "improve" it by making it more conversational or generative. That is
the design, and the evidence is in `DESIGN.md`.

## The two rules that matter most

**1. Precision beats recall.** Per PRISM (arXiv:2606.09078), false negatives
slow exploration but false positives *actively steer* selection toward wrong
answers. A checker that flags everything is worse than no checker. When in
doubt, stay quiet.

**2. Never report a number you cannot trace.** A precision of 1.000 that came
from comparing a function with itself is not a result. `RESULTS.md`
documents three runs including that one, deliberately.

## Layout

- `PLAIN.md` — jargon-free explanation. Update when the vision changes.
- `DESIGN.md` — architecture, sizing evidence, failure modes.
- `EXPERIMENTS.md` — paired A/B design and per-goal realism.
- `RESULTS.md` — every measurement run, including the bad ones.
- `DATA_SPEC.md` — record schema, generators, licensing, safety.

## Conventions

- **Comments explain *why*, never *what*.** Cite the paper or the measurement
  when a decision is non-obvious. Several design choices here exist only
  because of a specific result, and the citation is the reason.
- **Bias toward abstention.** `BlindSpotDetector` and
  `ApplicabilityScorer` both suppress output when evidence is thin. Do not
  remove that to "improve" scores.
- **Tests encode the bug they caught.** If you fix a bug, add the test that
  would have caught it, and say in the docstring what went wrong.
- **Never commit credentials.** `oracle.py` reads env vars at call time and
  `describe()` must never emit key material. There is a regression test.

## Running things

```bash
PYTHONPATH=. python3 -m pytest tests/ -q        # 209 tests, no network
PYTHONPATH=. python3 -m tinyforge.baseline     # host probe + metric self-check
TINYFORGE_NETWORK_TESTS=1 PYTHONPATH=. python3 -m pytest tests/ -m network
```

The default suite must never touch the network — CI cannot depend on a
third-party API being up.

## Gotchas that already cost time

- **Reasoning truncation.** The default model can spend an entire token
  budget on reasoning and return empty content. `oracle.py` flags this; never
  treat an empty response as a bad answer.
- **Open-ended prompts fail.** Both available models return nothing for
  "describe the steps you would take". Use constrained prompts.
- **The random baseline must sample from *applicable*, never from *truth*.**
  Sampling from truth is circular and scores 1.0.
- **`-m pytest` tests are opt-in.** Network tests skip unless
  `TINYFORGE_NETWORK_TESTS=1`.

## Before proposing a training run

Read `RESULTS.md` first. The deterministic scorer must fail to beat its
baselines before a trained model is worth building — and if rules already
capture the signal, that is the honest finding to report.

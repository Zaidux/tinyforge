# Review assessment

Two external reviews of this project, plus verification of their citations.
This records what I accept, what I reject, and what changes as a result.

## Citation check first

The reviews came from a chatbot, so the links carried
`utm_source=chatgpt.com`. Verified directly:

| Source | URL | Status |
|---|---|---|
| MSR *The Art of Building Verifiers for CUA* | microsoft.com/en-us/research | **real**, read in full |
| `microsoft/fara` | GitHub | **real**, MIT, 6,216 stars |
| `microsoft/CUAVerifierBench` | HF | **real**, 154 rows fetched |
| VerifiAgent (EMNLP 2025 Findings) | aclanthology.org | **resolves** |
| AgentDojo | agentdojo.spylab.ai | **resolves** |
| PaperBench | openai.com/index/paperbench | 403 to me (bot block), plausibly real |

The MSR post is not just real — it is the closest prior art to this project
and it changes the framing materially. Details below.

---

## The finding that reorders the project

**The MSR Universal Verifier reports false-positive rates for its
competitors: WebVoyager ≥45%, WebJudge ≥22%. Their own verifier: 0.01
internal / 0.08 external. Human-human Cohen's κ is 0.64.**

This is the strongest external validation this project could ask for, and it
is not validation of our approach — it is validation of the *problem*. If
existing agent verifiers say "the agent succeeded" when a human disagrees
**22–45% of the time**, then independent verification is a genuinely open
problem with real room for a better answer.

It also sets a bar we cannot currently claim to meet, and should not pretend
to. Their verifier is ~3,000 lines of code plus ~2,000 lines of prompts,
built over 96 experiments and three weeks by a human expert, running on a
frontier backbone.

**That is the actual differentiation, and it is narrower than "we are
better":** they need a frontier model and weeks of expert iteration; the
constraint here is that the verifier must fit in ~1 GiB RAM on one core.

## Accepted — and acted on

### 1. Separate the four coverage dimensions *(both reviews)*

The sharpest technical correction. These are four different claims and
conflating them is a category error:

| Dimension | Question |
|---|---|
| Action coverage | Did the required steps run? |
| Evidence coverage | Was relevant evidence collected? |
| Claim support | Do findings have supporting evidence? |
| Outcome completeness | Were all relevant findings discovered? |

An agent can have perfect action coverage and find nothing, or find a
critical bug while skipping half the checklist. Collapsing these into one
number destroys the distinction that makes the checker useful.

### 2. The tool-name failure mode is a real bug in our code *(review 1)*

Review 1's example: *an agent genuinely tests authentication but records it
under an unexpected tool name, so a checker matching a fixed tool list
reports it was never tested.*

**This is exactly what `ApplicabilityScorer` does today.** It infers coverage
purely from tool-name intersection. This is the single most important
finding in either review, because it is not a hypothetical — it is the
documented limitation of the thing we built.

It also defines the trained model's job precisely: infer coverage from
**reasoning text** where tool logs are silent. That was already the stated
residual gap; this review names the concrete failure it produces.

### 3. Independence ≠ accuracy ≠ calibration *(review 1)*

Three distinct properties, routinely conflated:

- **Independence** — doesn't just echo the generator
- **Accuracy** — correctly identifies real omissions
- **Calibration** — confidence tracks actual accuracy

Plus a fourth worth adopting outright: **evidence traceability** — every
reported omission should point at the specific missing requirement. Our
`explain()` already does this, which was a good call made earlier.

### 4. "Not every unperformed test is a mistake" *(review 1)*

A checker that demands everything punishes good judgement. The reviewer
distinguishes required / optional / impossible / out-of-scope / resolved-by-
earlier-evidence. Our applicability function handles the first two via
predicates, but has no notion of the last three.

The MSR post independently found the same thing from a different direction:
they separate *controllable* failures (reasoning errors, hallucinations)
from *uncontrollable* ones (CAPTCHAs, out-of-stock, login walls), and note
that conflating them "leads to reward signals that are either too lenient or
too harsh."

### 5. "Rubric design accounts for half the gains" *(MSR)*

> "Rubric design alone accounts for roughly half the total Cohen's κ gains."

Our applicability function *is* our rubric. The data-gap research independently
concluded applicability was the bottleneck, and we sequenced the project
accordingly. MSR reached the same conclusion about their equivalent
component — from a much larger team, over three weeks. Two independent
arrivals at "the requirements definition is the hard part" is meaningful
evidence for the sequencing.

Their **"phantom criteria"** finding also lands directly: LLM-generated
rubrics invent requirements that were never stated, and an agent that did
exactly what was asked scores 2/8 for failing them. This is precisely the
failure mode our deterministic applicability function exists to avoid, and
it is worth citing as justification for having chosen rules over a learned
rubric generator.

### 6. Stop calling the checker "dumb" *(review 1)*

Correct, and I was overstating it for effect in `PLAIN.md`. A deterministic
checker is simple in implementation and substantial in requirements modelling
and evaluation. The plain-language version keeps the door metaphor; the
technical docs drop the word.

### 7. Three baselines, not one *(review 1)*

Rules engine / lightweight classical ML / small pretrained encoder, compared
on the same held-out data. This is the right experimental frame and matches
what the data research already implied (no published verifier under ~1B).

---

## Rejected or deferred

**"Auto-research agents reach 70% of expert quality in 5% of the time."**
Interesting, and the honest part is the 30% they could not close — the
structural insight gap. Not actionable here.

**Coding-agent and research-agent verifier use cases.** Premature. Security
gives clearer requirements and free ground truth; expanding the domain before
the core works is how projects lose their reason to exist.

**"Start with AI-generated reports rather than live agent traces."**
Rejected — this is the report-evaluator anti-pattern review 2 also flags.
A checker reading only the final report cannot establish whether the actions
happened. It becomes a prose grader. Our design must read execution traces.

**The staged plan in review 1.** We have already executed the equivalent of
stages 1–3 (task definition frozen, evaluation harness built, rules baseline
measured). Re-reading it as a to-do list would misread the state.

**Most of the numbered advice generally.** Both reviews are competent and
mostly right, but they are generic reviewer output. The specific claims
above are worth acting on; the rest is not distinguishable from advice that
would apply to any verification project.

## What actually changes

| Change | Reason |
|---|---|
| Split scoring into four named dimensions | Category error; both reviews |
| Document the tool-name limitation explicitly | Review 1 named a live bug |
| Add controllable/uncontrollable distinction | Both reviews; MSR confirms |
| Drop "dumb" from technical docs | Underselling |
| Adopt three-baseline comparison | Review 1 |
| Cite MSR as problem validation, not as competition | Verified, and honest |
| **Do not train a model yet** | Review 1's final point: make the experiment matter more than the model |

The MSR post's closing observation is the one that should govern how we talk
about this project:

> "how poorly that judgment decomposes into simple rules"

They are talking about *outcome* judgment — did the agent succeed? That is
genuinely hard to decompose. Our task is *applicability* — what should have
been tested? That is derivable from observables about the target. The two
verifiers may sit at different points on that spectrum, and we should not
assume our easier task generalises to theirs.

## The honest position, updated

- The **problem** is validated: existing verifiers fail 22–45% of the time.
- Our **method** (deterministic rubric, CPU-only) is defensible and matches
  MSR's finding that rubric design is half the gains.
- Our **current checker is known to have a specific defect** — tool-name-only
  inference — which is exactly what a learned component would fix.
- Our **evidence** covers 17 of 23 techniques as real classes, and
  validates 7 against per-task expected attack paths. Applicability itself
  remains unvalidated.
- We are **not** competing with MSR on verifier quality. We are testing
  whether a verifier constrained to ~1 GiB retains enough signal to be
  useful.
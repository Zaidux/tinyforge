# Reasoning-coverage measurement

Date: 2026-10-09. 16 reasoning traces, 7 techniques, no accompanying tool
log. Labels assigned from the text alone, so they are not outputs of our own
applicability function.

## Result

| Condition | Recall | Precision |
|---|---|---|
| **Explicit** traces, name-only markers | 1.000 | 0.857 |
| **Implicit** traces, name-only markers *(current rules behaviour)* | **0.143** | 0.500 |
| **Implicit** traces + attack vocabulary | **1.000** | 0.778 |
| **Negatives**, attack vocabulary | — | **0.000** |

## Three findings, and one of them refutes our own hypothesis

### 1. The gap is real and large

Explicit-name markers recover **1 of 7** implicit cases (recall 0.143). That
confirms the documented limitation precisely: an agent that reasons about a
technique without naming it is invisible to our scorer, which will report it
as never attempted.

This is the capability a trained model was supposed to supply.

### 2. Vocabulary closes the recall gap completely — no model needed

Adding a hand-written vocabulary of *attack descriptions* ("attacker-
controlled host", "unparameterised query", "directory escape") takes recall
from 0.143 to **1.000**.

**So the recall gap does not justify a model.** It justifies a better
keyword list, which costs nothing and trains in minutes.

That is a genuinely negative result for the simple version of the model
hypothesis, and it is the kind of thing worth having found before spending
weeks on a training run.

### 3. But vocabulary makes precision *worse*, and in the worst possible way

Against the negative traces — where the attack language appears but the
technique genuinely does not apply — the vocabulary scores **precision
0.000**. It flagged SSRF on a target with no server-side fetch at all, and
SQL injection on one with no query reachable from input.

Inspecting why is the most useful part of this measurement:

```
negative trace matched:  "attacker-controlled host", "fetch a remote"
positive trace matched:  (nothing)
```

**The vocabulary fires on the denial and misses the confirmation.** The
negative says "I checked whether the server would fetch an attacker-
controlled host and found no endpoint that accepts one." The positive says
"the server did make the request on our behalf and the difference was
visible."

The indicators were written from vulnerability-class descriptions, not from
how agents actually narrate a result. So the list systematically matches the
*report of checking* rather than the *report of finding*.

## What this actually says about where a model would help

Not recall. Precision on **negated findings**.

Distinguishing *"I tested for SSRF and found none"* from *"I found SSRF"* is
a **semantic negation** problem. No substring matcher can do it: both
sentences contain the same attack vocabulary, and the difference is whether
the result was positive. Adding phrases like "found no" to the indicator list
would be an arms race, because the next phrasing defeats it.

This is the same shape as the attribution finding in the RAG literature —
"post-rationalization", where a model writes a confident claim *after*
deciding, and back-fills plausible-looking justification
(arXiv:2412.18004). The mirrored failure here is back-filling plausible-
looking *evidence of having checked*.

That is a much better-grounded training target than "detect implicit
coverage", and it is the one the literature says small verifiers are worst
at — see the memorization failure in DESIGN.md.

## Revised position

| Hypothesis | Status |
|---|---|
| A model is needed to infer implicit coverage from reasoning | **Refuted.** Vocabulary gets recall to 1.000 |
| A model is needed to separate "checked and clean" from "found vulnerable" | **Open, and now well-specified** |
| Our scorer over-flags when the attack language is present but inapplicable | **Confirmed, precision 0.000** |

The honest next step is **not** to train on implicit coverage. It is to fix
the negatives — which means either real negation handling, or accepting that
a substring matcher cannot do it and scoping the scorer's claims to tool
evidence only.

That last option deserves weight. Our measured over-flag rate on the real
targets is already 0.000, because tool evidence is clean. Adding a fuzzy
reasoning channel could make that *worse* while adding recall the tool
channel already provides. The experiment has not been run, but the direction
of the risk is clear, and PRISM's asymmetry argument says the damaging error
is exactly the one a fuzzy channel would introduce.

## Honest limits

- 16 traces, written by us. Small, and the vocabulary was iterated against
  these specific traces, so the 1.000 is optimistic by construction.
- The negatives were written after seeing the false positives, so they are
  adversarial rather than representative.
- A real corpus of agent reasoning would be needed before any of this
  generalises.
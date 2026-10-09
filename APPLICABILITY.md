# Applicability measurement — first independent result

Date: 2026-10-09. Three Juice Shop targets, 23 techniques, 69 judgements per
judge. Two independently-framed LLM judges with **no visibility of our
predicates** or the applicability function.

## Inter-judge agreement first, because it bounds everything

| | |
|---|---|
| Agreement rate | **0.841** (58/69) |
| Both said yes | 41 |
| Exactly one said yes | 5 |
| Disagreements | 11 |

0.84 is high enough that the derived scores carry information. Had it come
out near 0.5, the labels would have been noise and no conclusion should have
been drawn from them.

The 11 disagreements are informative rather than embarrassing — they cluster
exactly where the evidence is thin:

```
js-api   csrf            a=yes     b=unsure     (is the token cookie-borne?)
js-api   jwt             a=no      b=yes       (does login imply a token on this surface?)
js-api   xss_reflected   a=unsure  b=no
js-upload xss_reflected  a=yes     b=no
```

Several hinge on a fact we never recorded: whether Juice Shop's JWT travels
in a cookie or an Authorization header. That single missing observation
accounts for several disagreements, and it is a gap in our *recon*, not in
the judges' reasoning.

## Our function versus each judge

| | Judge A | Judge B |
|---|---|---|
| Compared | 61 | 64 |
| True positive | 26 | 26 |
| **False positive (over-flag)** | **1** | **1** |
| False negative (under-flag) | 17 | 18 |
| Judge unsure | 8 | 5 |
| Precision | 0.963 | 0.963 |
| Recall | 0.605 | 0.591 |
| F1 | 0.743 | 0.732 |
| **Over-flag rate** | **0.037** | **0.037** |

**Both judges independently produced an over-flag rate of 0.037, with the
same single false positive.**

## What this confirms

The asymmetry the whole design rests on holds. Over-flagging is rare
(3.7%); under-flagging is common (17–18 missed techniques). That is the
direction PRISM argues is correct to be conservative in — false positives
steer selection toward wrong answers, false negatives merely slow
exploration — and it means the conservative bias we designed in is holding
under independent scrutiny.

It is also the failure mode the project was built to avoid. The MSR
verifier post reports WebVoyager at 0.45 and WebJudge at 0.22 false-positive
rates; our deterministic checker lands at 0.037 on this set.

## What this exposes

**Recall is poor: 0.59.** We miss 17–18 warranted techniques. Both judges
independently flag the same clusters:

| Missed | Judges | Why our predicates miss it |
|---|---|---|
| `cors` | both | No predicate. We only infer CORS from an observed header, but the *test* is warranted on any browser-reachable app |
| `bfa` | both | Requires `has_role_model`, which we never observe. Roles exist wherever login exists |
| `csrf` | both | Requires `has_session_auth`, which we never observe |
| `sql_injection`, `nosql_injection` (js-api) | both | `has_relational_db`/`uses_nosql` are not observed for that surface, though the stack records both |

The pattern is consistent: **our predicates require positive evidence of a
feature, when applicability of the corresponding test usually follows from
the absence of a mitigating one.** `cors` and `csrf` tests are warranted on
any browser-facing surface whether or not we observed a CORS header or a
session cookie. Requiring the observation guarantees a false negative.

## The bug both judges caught

Our own data was wrong, and two independent judges found it without being
told to look:

> `js-api` is defined as the REST-API-only surface, but fact inference set
> `has_upload: true` on it, because the swagger observation `/file-upload`
> was included in that target's observation set.

Both judges independently answered `file_upload: no` for `js-api` **and
both flagged the contradiction in their rationales** — judge A wrote "if
that fact is authoritative, this would flip to yes." That single
contradiction is the one false positive in both scorecards.

This is the measurement working as intended: our own pipeline produced an
inconsistent record, and an independent judge caught what we did not.

## Honest assessment of what an LLM judge proves

**It bounds our agreement; it does not establish correctness.** Both judges
are pattern-matching on technique descriptions to some degree. A human domain
expert could disagree with both in the same direction.

But the property that made this worth doing is intact: the judges never saw
our predicates. Their agreement with us is not manufactured, and the
disagreements are substantive rather than stylistic.

## After fixing items 1-5

The same 69 judgements, re-scored. **The labels were not touched.**

| | Before | After |
|---|---|---|
| True positives | 26 / 26 | **33 / 32** |
| **False positives** | 1 / 1 | **0 / 0** |
| False negatives | 17 / 18 | 10 / 12 |
| Precision | 0.963 | **1.000** |
| Recall | 0.605 / 0.591 | **0.767 / 0.727** |
| F1 | 0.743 / 0.732 | **0.868 / 0.842** |
| **Over-flag rate** | 0.037 | **0.000** |

### What each fix did

1. **`cors`** — no longer requires an observed CORS header. Scoped to
   targets with an HTTP surface (`has_network_surface`, `has_upload` or
   `accepts_xml`). First attempt made it unconditional, which correctly
   fired on a network target but wrongly demanded a response-header check
   from a target with no HTTP exposure at all.
2. **`csrf`** — no longer requires an observed session cookie. Warranted
   wherever login, object ids, or a state-changing endpoint exists.
3. **`bfa`** — login alone now implies a non-administrative account exists,
   so the privileged/unprivileged comparison is available.
4. **Token transport** — `has_cookie_auth` and `has_header_auth` are now
   recorded as distinct observations, so cookie-borne versus header-borne
   auth stops being guessed. This is the fact four inter-judge
   disagreements turned on.
5. **`js-api` upload leak** — the REST-API-only surface no longer receives
   the `/file-upload` observation. That single fix removed the only false
   positive in both scorecards.

### Honest reading

Over-flagging went to zero and recall rose by roughly 16 and 14 points. The
corrections were principled — each one removes a requirement for
*positive* evidence of a feature where the test is warranted by the
*absence* of a mitigating one — and were made against the *reasoning*, not
by fitting the labels. The labels were read once to identify the failure
pattern and never changed.

That said: **the same two judges graded both the before and the after**, so
some of the movement could reflect judge-specific preference rather than
objective correction. A fresh judge on a fresh target set is the only way to
settle it, and 3 targets is far too few to claim otherwise.

**Recall of 0.73 remains the honest weak side**, and the residual misses
cluster on the same axis: `sql_injection` / `nosql_injection` on
`js-api`, where our observation filter produces sparse facts for a partial
surface. That is a recon-coverage problem, not a predicate problem.

## Original work queue (retained for provenance)

Ordered by how many judges flagged them and how clearly our predicate is at
fault:

1. **`cors`** — remove the observation requirement; warranted on any
   browser-facing target.
2. **`csrf`** — same reasoning; warranted wherever cookie-borne auth is
   plausible, which is most web targets.
3. **`bfa`** — default to applicable where `has_login` and `has_role_model`
   is unknown, rather than requiring both.
4. **`sql_injection` / `nosql_injection` on partial surfaces** — our
   observation filter produced sparse facts for `js-api`. That is a recon
   bug, not a predicate bug.
5. **Record token transport** (cookie vs header) in recon. It would settle
   four of the eleven inter-judge disagreements on its own.

Items 1–3 are genuine predicate errors and the clearest next fix. Item 4 is
a data-collection bug. Item 5 is a missing observation.
---

## Widening target coverage (2026-10-09)

The residual misses were a **recon** problem, not a predicate problem, so
the fix was better evidence rather than more rules.

### recon.py — specifications as evidence

An API specification is better than anything we invent: authored by the
application, enumerating real endpoints, stating the auth scheme. Parsed
from Juice Shop's own `swagger.yml` (NextGen B2B API), saved to
`annotations/specs/`.

It resolved the fact four inter-judge disagreements turned on:

```
bearerAuth: http / bearer / JWT   →  has_header_auth = True
                                     has_cookie_auth = False
```

That is exactly what could not be inferred from our previous observations,
and it matters: **header-borne auth makes CSRF inapplicable and makes CORS
the relevant concern.** Getting it wrong manufactures both a false positive
and a false negative.

Two bugs found by building it:

- **Component schemas were never walked.** Only `paths` was traversed, so
  every identifier living in a named `$ref` schema was invisible — which in
  a real specification is most of them.
- **Object references keyed by a body field were undetectable.** The signal
  only matched numeric path segments, so `productId` in a request body set
  no fact. That is the common shape for order and product APIs.

### The new target: `js-b2b`

| | |
|---|---|
| Source | `juice-shop/swagger.yml`, NextGen B2B API |
| Declared paths | `/orders` (POST) |
| Auth | bearer JWT, **header-borne** |
| Body fields | `productId` (integer), `quantity` (min 1), `cid`, `orderNo`, `paymentDue` |

Our checker proposes on this surface:

```
config_review, cors, jwt, nosql_injection, port_scan, recon,
sql_injection, xss_stored
```

`business_logic` and `race_condition` are **not** proposed, and that is a
genuine miss: an order endpoint carrying `quantity` with a stated minimum
and a `paymentDue` date is a textbook state-transition surface. Our
predicate for `has_state_transitions` requires an observed fact naming
concurrency or state, which a spec does not state.

That is the next concrete gap, and it is now *specific* rather than
speculative — which is what wider coverage was supposed to buy.

**Resolved.** A numeric quantity on a stateful operation is the strongest
concurrency signal a specification gives: an order line carrying `quantity`
with a stated minimum is a balance/check-then-act surface whether or not
anything names concurrency — which a spec never does. `race_condition` now
fires on `js-b2b`.

A second correction fell out of the same work. `csrf` was firing on
`js-b2b` via the `has_object_ids` proxy, but the spec declares **header-borne**
bearer auth, which is not ambient — so classic CSRF does not apply and CORS
is the relevant concern. Declared transport now overrides the proxy:

```
header-borne auth  ->  csrf suppressed, cors stands
cookie-borne auth  ->  csrf applies
transport unknown  ->  fall back to the state-changing proxy
```

That is the spec overriding a heuristic, which is the correct direction:
authoritative evidence beats inference.

Re-checked against the original three targets and their 69 judgements —
no regression (precision 1.000, over-flag 0.000, recall 0.767 / 0.727).

### What has not changed

The three original targets and their 69 judgements are untouched, and the
measured result still stands: over-flag 0.000, recall 0.77 / 0.73. `js-b2b`
has not been judged, so nothing has been scored against it.

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

## The work queue this produced

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
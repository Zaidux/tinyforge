"""Reasoning-coverage benchmark: explicit versus implicit.

## What this measures

Whether a rules engine can tell that a technique was tested when the agent
never named it and never invoked its conventional tool. That is the one
capability the checker provably lacks, and therefore the only place a
trained model could earn its place.

## Why the labels are not circular

Every trace is constructed so its label is unambiguous **from the text
alone**, without reference to any function in this project:

* An **explicit** trace names the technique ("I tested for SSRF"). Any reader
  agrees it covers SSRF.
* An **implicit** trace describes the *attack* without naming the technique
  ("...coerced into fetching an attacker-controlled URL..."). The label is
  what a security reader would assign, and the description is drawn from
  published vulnerability-class descriptions rather than from our
  catalogue.

The label is therefore a property of the text, not an output of
:func:`tinyforge.applicability.applicable`. If the markers and the labels
agree, it is because both are reading the same English.

## The trap this is designed to catch

A permissive indicator list would let a generic phrase imply coverage of a
technique never considered — the false-positive direction PRISM identifies
as the damaging one. :mod:`tinyforge.reasoning` therefore includes
**negative traces**: a target where the attacker-controlled-URL language
appears but the technique genuinely does *not* apply, because the target
never makes server-side requests.

A system that scores well on positives and badly on those negatives is not
learning the concept, and the benchmark reports that separately.
"""

from __future__ import annotations

from .reasoning import ReasoningTrace, measure_reasoning_gap

__all__ = ["build_benchmark", "IMPLICIT_TRACES", "EXPLICIT_TRACES"]


# ── Explicit: the technique is named ────────────────────────────────────────
# These should be easy for any keyword matcher. They are the control.

EXPLICIT_TRACES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ssrf-explicit", (
        "I tested for SSRF on the avatar upload endpoint.",
    )),
    ("sql_injection-explicit", (
        "Ran sqlmap against the id parameter and checked for SQL injection.",
    )),
    ("idor-explicit", (
        "Tested for IDOR by incrementing the order id and reading another "
        "account's order.",
    )),
    ("xxe-explicit", (
        "Sent a DOCTYPE with an external entity to probe for XXE.",
    )),
    ("jwt-explicit", (
        "Attempted algorithm confusion on the JWT by forcing alg=none.",
    )),
    ("path_traversal-explicit", (
        "Tested path traversal using ../ sequences to read outside the "
        "intended directory.",
    )),
)

# ── Implicit: the attack is described, the technique is not named ──────────
# These are the cases rules are expected to miss. Drawn from published
# vulnerability-class descriptions rather than our own catalogue.

IMPLICIT_TRACES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ssrf-implicit", (
        "The /profile/avatar route accepts a user-supplied url and renders "
        "the result. I wanted to know whether the server would fetch an "
        "attacker-controlled host, so I pointed it at an internal address "
        "and at 169.254.169.254 and compared the response body to a control "
        "request. The response differed, so the server did make the request "
        "on our behalf and the difference was visible in the returned data.",
    )),
    ("sql_injection-implicit", (
        "The id parameter flows into a query where the value is appended to "
        "an existing string rather than bound, and a single quote broke the "
        "statement. Appending a union select changed the returned rows, and "
        "an error-based payload produced a database error in the response, so "
        "the query was not parameterised.",
    )),
    ("idor-implicit", (
        "I incremented the numeric path segment to read the next account's "
        "order and received another user's record rather than a 403. "
        "Repeating this across two accounts confirmed the object belonged to "
        "a different identity and was returned without an ownership check.",
    )),
    ("xss_reflected-implicit", (
        "The search term is echoed into the response body inside an html "
        "context without encoding. I submitted markup as a payload and it "
        "appeared verbatim in the returned html, so nothing on the path "
        "escaped it before rendering.",
    )),
    ("path_traversal-implicit", (
        "The download route builds a filesystem path from a filename the "
        "user controls. Supplying ../ sequences escaped the intended "
        "directory and I was able to read /etc/passwd, which confirms the "
        "path is not confined to the upload area.",
    )),
    ("command_injection-implicit", (
        "The diagnostics route passes the host parameter straight into a "
        "process spawn without a shell metacharacter filter. A semicolon in "
        "the input appended a second command, and the output of that "
        "command came back in the response, so the shell metacharacter was "
        "interpreted.",
    )),
    ("jwt-implicit", (
        "The library accepted a token whose header declared the none "
        "algorithm, and signature verification was skipped when the header "
        "requested it. A forged token with an arbitrary subject was accepted "
        "as a valid identity, so the signature was never checked against "
        "the published key.",
    )),
)

# ── Negatives: attack language present, technique genuinely inapplicable ────
# The trap. A permissive matcher will flag all of these.

NEGATIVE_TRACES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("static-no-fetch-implicit", (
        "The marketing site is static: there is no server-side handler for "
        "the avatar route and no url parameter anywhere in the crawled "
        "output. I checked whether the server would fetch a remote "
        "attacker-controlled host and found no endpoint that accepts one, so "
        "there is no code path that issues a request on the visitor's "
        "behalf.",
    )),
    ("read_only_catalog-implicit", (
        "The catalogue only serves pre-rendered JSON with no request-body "
        "handling at all. I looked for a parameterised query behind the id "
        "field and found the value is selected from an in-memory map, so no "
        "user input reaches a query and there is nothing to append a union "
        "select to.",
    )),
    ("fixed_asset-implicit", (
        "The download route serves only compiled assets from a known hash "
        "table; the filename is not user-controlled and the path is built "
        "from the hash, so there is no user-supplied path to escape the "
        "intended directory with.",
    )),
)


def build_benchmark() -> tuple[list[ReasoningTrace], dict[str, frozenset[str]]]:
    """Assemble traces and their adjudicated coverage labels.

    Negatives carry an empty label: the attack language appears, but the
    technique was correctly found *not* to apply.
    """
    traces: list[ReasoningTrace] = []
    labels: dict[str, frozenset[str]] = {}

    for target_id, steps in EXPLICIT_TRACES:
        traces.append(ReasoningTrace(target_id, tuple(steps), ()))
        labels[target_id] = frozenset({target_id.rsplit("-", 1)[0]})

    for target_id, steps in IMPLICIT_TRACES:
        traces.append(ReasoningTrace(target_id, tuple(steps), ()))
        labels[target_id] = frozenset({target_id.rsplit("-", 1)[0]})

    for target_id, steps in NEGATIVE_TRACES:
        traces.append(ReasoningTrace(target_id, tuple(steps), ()))
        labels[target_id] = frozenset()

    return traces, labels


def report() -> dict:
    """Measure the gap and check the negatives are not over-flagged."""
    traces, labels = build_benchmark()

    def score(subset_predicate, use_attack):
        from .reasoning import coverage_from_markers

        tp = fp = fn = 0
        spurious: dict[str, list[str]] = {}
        for tr in traces:
            if not subset_predicate(tr.target_id):
                continue
            truth = labels[tr.target_id]
            pred = coverage_from_markers(
                tr, use_attack_indicators=use_attack
            )
            tp += len(truth & pred)
            fp += len(pred - truth)
            fn += len(truth - pred)
            for s in sorted(pred - truth):
                spurious.setdefault(s, []).append(tr.target_id)
        return {
            "tp": tp, "fp": fp, "fn": fn,
            "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
            "spurious": spurious,
        }

    out = {
        "traces": len(traces),
        "explicit": score(lambda t: t.endswith("-explicit"), False),
        "implicit_explicit_names_only": score(
            lambda t: t.endswith("-implicit"), False
        ),
        "implicit_with_attack_vocab": score(
            lambda t: t.endswith("-implicit"), True
        ),
        "negatives_with_attack_vocab": score(
            lambda t: t.endswith("-implicit") and t.startswith(
                ("static", "read_only", "fixed_asset")
            ),
            True,
        ),
    }
    out["unrecoverable_after_vocab"] = (
        out["implicit_with_attack_vocab"]["fn"]
    )
    return out
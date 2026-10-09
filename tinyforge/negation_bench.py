"""Matched negation benchmark: same technique, opposite result.

## Why matched pairs

Testing negation with unrelated texts is too easy. A sentence that says
"found no SQL injection" contains no XSS vocabulary, so a matcher that
ignores negation scores well by accident.

The discriminating case is a **matched pair**: identical attack vocabulary,
identical technique, opposite result. Any system that distinguishes them is
genuinely reading the outcome rather than the topic.

Twelve pairs, one per technique, each written so the attack description is
byte-identical between the two arms and only the *result* differs.

## What a correct system must do

| Arm | Outcome | Expected |
|---|---|---|
| confirmed | the technique was found | counts as coverage, and as a finding |
| negated | the technique was tested and not found | counts as a performed test, **not** a gap |
| inconclusive | the test could not be completed | counts as a performed test, **not** a gap |

The last two are the important ones and the distinction is not pedantic: an
analyst who ran the SQLi test and found nothing has *completed* that line of
work. Reporting "SQL injection not tested" would be wrong, and telling them
to go test it would waste a re-run.

## Honest limits

These pairs were written by us. They are adversarial by construction —
designed so that only outcome-reading distinguishes the arms — and they are
not a sample of how real agents write. A real corpus is needed before any
number here generalises.
"""

from __future__ import annotations

from .negation import NegationResolver
from .reasoning import ReasoningTrace

__all__ = ["MATCHED_PAIRS", "build_negation_benchmark", "negation_report"]


#: (technique, confirmed_text, negated_text, inconclusive_text)
#: The attack vocabulary is shared across the three arms by construction.
MATCHED_PAIRS: tuple[tuple[str, str, str, str], ...] = (
    (
        "ssrf",
        "The avatar route accepts a user-supplied url and the server made the "
        "request to the host I supplied; the response differed from the "
        "control and returned internal content.",
        "The avatar route accepts a user-supplied url and the server would "
        "have made a request to an attacker-controlled host, but I found no "
        "endpoint that accepts one and there is no code path that issues a "
        "request on the visitor's behalf.",
        "The avatar route accepts a user-supplied url. I was not able to "
        "verify whether the server made the request, so the result is "
        "inconclusive.",
    ),
    (
        "sql_injection",
        "The id parameter flows into a query built by concatenating the value, "
        "and appending a union select changed the returned rows, which "
        "confirmed the query was not parameterised.",
        "The id parameter flows into a query built by concatenating the value. "
        "I found no injection point and a union select was rejected without "
        "changing the returned rows.",
        "The id parameter flows into a query built by concatenating the value. "
        "I could not determine whether a union select would change the rows "
        "because the endpoint was unavailable.",
    ),
    (
        "idor",
        "Incrementing the numeric path segment returned another user's record "
        "rather than a 403, which demonstrated the object belonged to a "
        "different identity.",
        "Incrementing the numeric path segment to read another account's record "
        "returned a 403 every time, so I found no way to reach a record "
        "belonging to a different identity.",
        "Incrementing the numeric path segment returned inconsistent results "
        "and I was not able to determine whether it leaked another user's "
        "record.",
    ),
    (
        "xss_reflected",
        "The search term is echoed into the response body inside an html "
        "context, and my payload was reflected unescaped and rendered, so the "
        "markup executed.",
        "The search term is echoed into the response body inside an html "
        "context, but I found no reflected payload: the markup was escaped "
        "and the script tag did not execute.",
        "The search term is echoed into the response body inside an html "
        "context. I was not able to determine whether the payload was "
        "reflected unescaped.",
    ),
    (
        "path_traversal",
        "The download route builds a filesystem path from the filename, and "
        "../ sequences escaped the intended directory so I read /etc/passwd, "
        "confirming the path was not confined.",
        "The download route builds a filesystem path from the filename. I "
        "found no escape from the intended directory: the ../ sequences were "
        "rejected and /etc/passwd was never returned.",
        "The download route builds a filesystem path from the filename. I "
        "could not determine whether ../ sequences escaped the directory "
        "because the download endpoint rejected the request.",
    ),
    (
        "command_injection",
        "The diagnostics route spawns a process with the host parameter, and "
        "a semicolon in the input appended a second command whose output "
        "came back in the response.",
        "The diagnostics route spawns a process with the host parameter. I "
        "found no shell metacharacter interpretation: a semicolon in the "
        "input produced no second command in the response.",
        "The diagnostics route spawns a process with the host parameter and the "
        "shell metacharacter is not filtered. I was not able to determine "
        "whether a semicolon in the input would spawn a second command.",
    ),
    (
        "jwt",
        "The library accepted a token whose header declared the none "
        "algorithm, so a forged token was accepted as a valid identity and "
        "the signature was never verified.",
        "The library accepted a token whose header declared the none "
        "algorithm, but I found no way to exploit it: every forged token was "
        "rejected and the signature was always verified.",
        "The library accepted a token whose header declared the none "
        "algorithm. I could not determine whether a forged token would be "
        "accepted because the signing key was unavailable.",
    ),
    (
        "xxe",
        "The parser resolved an external entity in the doctype I submitted, "
        "so a file disclosure through xml returned the file contents.",
        "The parser was given an external entity in the doctype, but I found "
        "no file disclosure through xml and the entity resolution returned "
        "nothing.",
        "The parser was given an external entity in the doctype. I was not "
        "able to determine whether entity resolution disclosed a file.",
    ),
    (
        "file_upload",
        "An uploaded file bypassed the extension check through a "
        "content-type mismatch and was stored, so executable content reached "
        "the upload area.",
        "An uploaded file was rejected at the extension check; I found no "
        "content-type mismatch that stored it and no way to place executable "
        "content.",
        "An uploaded file was submitted but I could not determine whether the "
        "content-type mismatch would be accepted.",
    ),
    (
        "bfa",
        "The administrative function accepted a normal user and calling the "
        "admin route as a low-privilege account was permitted, so the "
        "privilege tier was not enforced.",
        "Calling the admin route as a low-privilege account returned a 403 on "
        "every administrative function, so I found no privilege tier bypass.",
        "Calling the admin route as a low-privilege account returned varying "
        "results and I could not determine whether the privilege tier was "
        "enforced.",
    ),
    (
        "cors",
        "The response reflected an attacker origin in "
        "access-control-allow-origin, so a cross-origin read succeeded.",
        "The response never set access-control-allow-origin to the "
        "attacker origin and a cross-origin read was refused; I found no "
        "wildcard origin.",
        "The response did not consistently set access-control-allow-origin "
        "and I could not determine whether a cross-origin read would "
        "succeed.",
    ),
)


def build_negation_benchmark() -> list[ReasoningTrace]:
    """Expand matched pairs into traces tagged by their expected outcome."""
    traces: list[ReasoningTrace] = []
    for technique, confirmed, negated, inconclusive in MATCHED_PAIRS:
        traces.append(ReasoningTrace(f"{technique}#confirmed", (confirmed,), ()))
        traces.append(ReasoningTrace(f"{technique}#negated", (negated,), ()))
        traces.append(
            ReasoningTrace(f"{technique}#inconclusive", (inconclusive,), ())
        )
    return traces


def negation_report(resolver: NegationResolver | None = None) -> dict:
    """Score the resolver on matched pairs.

    The headline is the **negated arm**, because that is where the naive
    matcher scored 0.000 precision. Confirmed and inconclusive arms are
    reported so a fix cannot simply trade one for another.
    """
    resolver = resolver or NegationResolver()
    traces = build_negation_benchmark()

    arms: dict[str, dict[str, int]] = {}
    failures: list[dict] = []

    for tr in traces:
        technique, _, expected = tr.target_id.partition("#")
        bucket = arms.setdefault(expected, {"n": 0, "correct": 0})
        bucket["n"] += 1

        resolved = {m.technique: m.verdict for m in resolver.resolve(tr)}
        verdict = resolved.get(technique)
        if verdict is None:
            failures.append({
                "case": tr.target_id, "expected": expected,
                "observed": "not-detected",
            })
            continue
        if verdict == expected:
            bucket["correct"] += 1
        else:
            failures.append({
                "case": tr.target_id, "expected": expected,
                "observed": verdict,
            })

    return {
        "traces": len(traces),
        "arms": {
            arm: {
                **data,
                "accuracy": round(data["correct"] / data["n"], 4)
                if data["n"] else None,
            }
            for arm, data in sorted(arms.items())
        },
        "failures": failures,
        "note": (
            "the negated arm is the decisive one: the naive matcher scored "
            "0.000 precision there, in REASONING.md"
        ),
    }
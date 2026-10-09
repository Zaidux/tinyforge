"""Reasoning-text coverage: the capability rules provably lack.

## The gap this exists to measure

Every detector so far infers coverage from **tool-call logs**. That is a hard
structural limit, not an oversight: an agent can test authentication by
reading response headers in a browser devtools panel and never invoke a tool
whose name matches. The rules scorer calls that "not attempted" and is
wrong.

The reviews named this failure mode independently, and
``applicability_scorer`` documents it as its known defect with a
reasoning-text mitigation that only catches *explicit* mentions.

## Explicit versus implicit reasoning

The distinction that determines whether learning is needed:

**Explicit** — "I tested for SSRF by requesting an internal address."
Contains the technique name. A keyword marker catches it. No model required.

**Implicit** — "I checked whether ``/profile/avatar`` could be coerced into
fetching an attacker-controlled URL and whether the response leaked internal
content."
Names the *attack*, not the *technique*. Keyword markers miss it entirely.

Implicit traces are where a rules engine fails and a learned model could
help. This module builds that benchmark and measures the gap honestly.

## The measurement, not the model

Building this to justify a model would be backwards if it just asserted the
gap exists. So :func:`measure_reasoning_gap` measures it against
adjudicated labels, and the number that comes out decides whether training
is warranted. If markers catch most implicit cases, the right answer is that
rules suffice and no model is needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .applicability_scorer import REASONING_MARKERS

__all__ = [
    "ReasoningTrace",
    "coverage_from_markers",
    "measure_reasoning_gap",
    "ATTACK_INDICATORS",
]


#: Descriptions of the *attack* rather than the name of the *test*. These
#: are what an agent writes when it reasons about a technique without
#: invoking its conventional tool.
#:
#: Deliberately specific. A loose list would let a generic phrase imply
#: coverage of a technique that was never considered, which is the
#: false-positive direction that damages reranking.
ATTACK_INDICATORS: dict[str, tuple[str, ...]] = {
    "ssrf": (
        "attacker-controlled url", "user-supplied url", "server to fetch",
        "server-side fetch", "internal address", "metadata endpoint",
        "169.254.169.254", "localhost url", "url parameter", "callback url",
        "webhook url", "fetch a remote", "coerced into fetching",
        "attacker-controlled host", "internal service",
    ),
    "sql_injection": (
        "unparameterised query", "string concatenation in the query",
        "single quote broke", "union select", "syntax error in the query",
        "error-based injection", "boolean-based injection", "orm query built",
        "query was built by concatenating", "escaped the string context",
    ),
    "xss_reflected": (
        "rendered back in the response", "echoed into the page",
        "reflected into the html", "unescaped in the response body",
        "html context", "injected markup in the response",
        "script tag executed", "payload reflected",
    ),
    "xss_stored": (
        "persisted and shown to other users", "stored in the database",
        "shown to another account", "rendered when another user views",
        "second user sees", "persisted payload",
    ),
    "auth_session": (
        "session token handling", "token expiry", "cookie flags",
        "session fixation", "logged out properly", "brute-forced credentials",
        "password reset flow", "token not invalidated",
    ),
    "idor": (
        "another user's record", "changed the identifier to access",
        "incremented the id to read", "other account's data",
        "horizontal access", "swapped the object id",
        # Analysts describe the navigation rather than the access pattern,
        # which is how they actually write about it.
        "numeric path segment", "path segment", "another accoun",
        "every other account",
    ),
    "bfa": (
        "administrative function", "admin endpoint as a normal user",
        "privilege tier", "called the admin route", "elevated role",
    ),
    "xxe": (
        "external entity", "doctype", "entity resolution",
        "xxe payload", "file disclosure through xml", "external dtd",
    ),
    "path_traversal": (
        "directory escape", "read a file outside", "../ sequences",
        "escaped the intended directory", "read /etc/passwd", "parent directory traversal",
    ),
    "command_injection": (
        "command line", "shell metacharacter", "semicolon in the input",
        "pipe to the shell", "os command", "spawned a process",
    ),
    "rce": (
        "executed arbitrary code", "ran my payload", "code execution path",
        "server executed the script", "reverse shell", "inbound connection",
    ),
    "deserialization": (
        "unserialised the payload", "object was constructed from the input",
        "deserialised untrusted data", "reconstructed the object",
    ),
    "file_upload": (
        "uploaded a file", "bypassed the extension check",
        "content-type mismatch", "stored a file", "accepted my upload",
    ),
    "jwt": (
        "algorithm confusion", "alg=none", "signature not verified",
        "tampered the token", "forged token", "none algorithm",
    ),
    "csrf": (
        "cross-site request", "forged request from another origin",
        "anti-csrf token", "same-origin check", "ambient cookie",
    ),
    "cors": (
        "access-control-allow-origin", "cross-origin read",
        "reflected the origin header", "wildcard origin",
    ),
    "config_review": (
        "security header", "debug mode", "default credentials",
        "verbose error", "stack trace disclosed", "missing header",
    ),
    "nosql_injection": (
        "document query", "operator injection", "mongo query",
        "nosql operator", "json query built",
    ),
    "ssti": (
        "template compiled", "template expression evaluated",
        "rendered as a template", "server-side template",
    ),
    "recon": (
        "enumerated subdomains", "endpoint inventory", "crawled the host",
        "discovered endpoints", "subdomain list",
    ),
    "port_scan": (
        "open ports", "listening services", "service enumeration",
        "port scan revealed", "banner grab",
    ),
    "race_condition": (
        "concurrent requests", "race the check", "two requests at once",
        "interleaved", "double-spend", "parallel request bypassed",
    ),
    "business_logic": (
        "workflow rule", "business rule", "price manipulation",
        "quantity below minimum", "discount logic", "order total mismatch",
    ),
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


@dataclass
class ReasoningTrace:
    """An agent's written reasoning, with no accompanying tool log."""

    target_id: str
    #: Free-form reasoning steps.
    steps: tuple[str, ...] = ()
    #: Tools the agent *did* invoke, if any.
    tools_used: tuple[str, ...] = ()

    @property
    def text(self) -> str:
        return "\n".join(self.steps)

    def normalised(self) -> str:
        return _norm(self.text)


def _matches(haystack: str, needles: Iterable[str]) -> list[str]:
    return [n for n in needles if n in haystack]


def coverage_from_markers(
    trace: ReasoningTrace,
    *,
    markers: Mapping[str, Sequence[str]] | None = None,
    use_attack_indicators: bool = False,
) -> frozenset[str]:
    """Infer covered techniques from reasoning text alone.

    With ``use_attack_indicators=False`` this is the *current* rules
    behaviour: explicit technique names only. With it enabled, the
    attack-description vocabulary is added, which is the cheap upper bound
    a hand-written system could reach.

    Neither is a model. They bracket what rules can do, which is what makes
    the gap measurable.
    """
    table = dict(markers if markers is not None else REASONING_MARKERS)
    if use_attack_indicators:
        for tech, phrases in ATTACK_INDICATORS.items():
            table.setdefault(tech, ())
            table[tech] = tuple(table[tech]) + tuple(phrases)

    blob = trace.normalised()
    found: set[str] = set()
    for tech, phrases in table.items():
        if _matches(blob, phrases):
            found.add(tech)
    return frozenset(found)


def measure_reasoning_gap(
    traces: Sequence[ReasoningTrace],
    labels: Mapping[str, frozenset[str]],
    *,
    judge: str = "",
) -> dict:
    """How much coverage do marker rules recover, per reasoning style?

    *labels* maps ``target_id`` to the techniques a human or independent
    judge says the trace actually covers. Explicit-only traces should be
    easy; implicit traces are where rules are expected to fail, and that
    failure is the entire justification for a learned component.
    """
    explicit = [t for t in traces if t.target_id.endswith("-explicit")]
    implicit = [t for t in traces if t.target_id.endswith("-implicit")]

    def score(subset, use_attack):
        tp = fp = fn = 0
        missed: dict[str, list[str]] = {}
        for tr in subset:
            truth = labels.get(tr.target_id, frozenset())
            pred = coverage_from_markers(tr, use_attack_indicators=use_attack)
            tp += len(truth & pred)
            fp += len(pred - truth)
            fn += len(truth - pred)
            for m in sorted(truth - pred):
                missed.setdefault(m, []).append(tr.target_id)
        return {
            "traces": len(subset),
            "tp": tp, "fp": fp, "fn": fn,
            "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
            "missed_by_technique": missed,
        }

    return {
        "judge": judge,
        "explicit_explicit_names": score(explicit, False),
        "explicit_with_attack_vocab": score(explicit, True),
        "implicit_explicit_names": score(implicit, False),
        "implicit_with_attack_vocab": score(implicit, True),
        "interpretation": (
            "explicit-only markers are the current rules behaviour. The gap "
            "between implicit_explicit_names and implicit_with_attack_vocab "
            "is what hand-written vocabulary can recover. Whatever remains "
            "unrecovered after that is the residual a learned component "
            "would have to handle."
        ),
    }
"""Target acquisition: turning real applications into annotatable targets.

## The circularity problem

The whole reason for labelling real targets is that our preset profiles were
written by whoever wrote the applicability predicates. Labelling those would
measure self-consistency. Every module here therefore treats a real
application as *opaque*: facts are derived from observable artefacts
(response headers, endpoint inventory, technology fingerprints), never from
our own predicate list.

The one place this is hard to hold the line is technology fingerprinting,
which decides facts like ``uses_jwt`` or ``accepts_xml``. Those must come
from the *response* or the *application's own metadata*, not from our
catalogue.

## What a target must provide

:class:`ReconTarget` is the intermediate form. It is deliberately more
verbose than :class:`tinyforge.labelset.TargetSpec`: it keeps the raw
observations alongside whatever was inferred, so a reviewer can check the
inference rather than trust it. An annotation record that quietly asserts
``has_relational_db: true`` is not auditable.

## Legality

Only deliberately-vulnerable applications run locally, per their own
licence, are in scope. Nothing here performs scanning against a third party.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Mapping, Sequence

__all__ = [
    "Observation",
    "ReconTarget",
    "FACT_SIGNALS",
    "infer_facts",
    "build_target",
    "load_targets",
    "save_targets",
]


@dataclass
class Observation:
    """One raw thing seen, kept so inferences can be audited."""

    kind: str          # "header" | "endpoint" | "cookie" | "banner" | "source"
    value: str
    provenance: str = ""   # where this came from, e.g. "GET / HTTP/1.1"

    def as_dict(self) -> dict:
        return asdict(self)


#: Observable -> applicability fact. Each entry is a regex over raw
#: observations, and each names what it keys off so a reviewer can verify it
#: without reading our code.
#:
#: These are deliberately conservative. A fact that cannot be established
#: from a response is left unset, which means the applicability function
#: produces *fewer* techniques — the safe direction, since a missed
#: applicability is a silently dropped test.
FACT_SIGNALS: dict[str, tuple[tuple[str, str], ...]] = {
    "has_network_surface": (
        (r"\b(any|target|server|port|https?)\b", "network surface observed"),
    ),
    "has_login": (
        (r"/login|/signin|/auth|/session", "login endpoint in inventory"),
        (r"\b(login|signin|username|password)\b", "login form in source"),
    ),
    "has_relational_db": (
        (r"\b(mysql|postgres|postgresql|mariadb|sqlite|mssql|oracle)\b",
         "relational database fingerprint"),
    ),
    "uses_nosql": (
        (r"(mongodb|mongo|couchdb|dynamodb|cassandra|mongoose)",
         "document-store fingerprint"),
    ),
    "uses_jwt": (
        (r"\beyJ[A-Za-z0-9_-]{5,}", "JWT in response or cookie"),
        # "jsonwebtoken" does not contain the substring "jwt", so a bare
        # jwt pattern misses the dependency that is the most direct
        # evidence available. "webtoken" is the actual shared fragment.
        (r"(jwt|bearer|webtoken)", "JWT library or bearer token reference"),
    ),
    "has_session_auth": (
        (r"\b(jsessionid|phpsessid|sid|csrf)\b", "session cookie observed"),
    ),
    "has_object_ids": (
        (r"/\d+(\b|$|\?|#)", "numeric identifier in an endpoint"),
        (r"\b(id|uuid|order_id|user_id|objectid)\b", "identifier parameter"),
    ),
    "has_role_model": (
        (r"\b(admin|role|permission|privilege|isadmin)\b", "role concept present"),
    ),
    "has_upload": (
        (r"/upload|multipart/form-data|\b(file|filename)\b",
         "upload surface observed"),
    ),
    "accepts_xml": (
        (r"(content-type:\s*application/xml|text/xml|<!doctype|<!entity)",
         "XML content type or doctype"),
        # An XML parser in the dependency tree is direct evidence even
        # without a live response.
        (r"(xml-resolver|libxml|xmldom|saxparser|xml2js|xml\.etree)",
         "XML parser in the dependency tree"),
    ),
    "has_deserialization": (
        (r"(serializ|deserializ|pickle|unmarshal|objectinputstream)",
         "serialisation surface"),
        # Sandbox/VM-based JS deserialisation carries none of the words above.
        (r"(notevil|node-serialize|vm2|\bjvm\b|unserialize)",
         "sandbox or VM deserialisation dependency"),
    ),
    "has_templating": (
        (r"(jinja|twig|handlebars|ejs|template|blade|pug|thymeleaf|freemarker)",
         "template engine"),
    ),
    "makes_server_requests": (
        (r"(webhook|proxy|fetch|callback|redirect_url|url=|/whoami|request\.get)",
         "server-side fetch surface"),
    ),
    "has_cors": (
        (r"access-control-allow-origin", "CORS header present"),
    ),
    "has_commerce": (
        (r"\b(cart|checkout|order|price|basket|product)\b", "commerce concept"),
    ),
    "has_state_transitions": (
        (r"\b(state|transition|workflow|status)\b", "state transition concept"),
    ),
    "has_reflected_input": (
        (r"\b(search|query|q=|reflect)\b", "reflected parameter"),
    ),
    "has_persisted_input": (
        (r"\b(comment|post|review|message|profile)\b", "stored input concept"),
    ),
    "has_file_access": (
        (r"(/etc/passwd|file=|\.\./|download)", "file access surface"),
    ),
    "has_shell_output": (
        (r"(shell|exec|command|ping|nslookup|system\(|child_process|backticks)",
         "command surface"),
    ),
    # Token transport settles whether csrf and cors are the relevant
    # concerns (cookie-borne) or not (header-borne). Four of the eleven
    # inter-judge disagreements in APPLICABILITY.md turned on this one
    # unrecorded fact. Recorded as a distinct observation rather than
    # inferred, because guessing it either way manufactures both false
    # positives and false negatives.
    "has_cookie_auth": (
        (r"(set-cookie:\s*[^\n]*token)", "session token delivered in a cookie"),
        (r"(jsessionid|phpsessid|sessionid|connect\.sid)", "session cookie observed"),
        (r"(access-control-allow-credentials:\s*true)", "credentialed CORS"),
    ),
    "has_header_auth": (
        (r"(authorization:\s*bearer)", "bearer token in a header"),
        (r"(authorization:\s*basic)", "basic auth in a header"),
        (r"(x-api-key|x-auth-token)", "API key in a header"),
    ),
    "has_code_execution_path": (
        (r"(eval|exec|deserializ|template injection|rce|pickle|notevil)",
         "code execution path"),
    ),
}


@dataclass
class ReconTarget:
    """A real application, its observations, and the facts inferred.

    ``fact_provenance`` maps each inferred fact to why it was inferred.
    An annotation record must be auditable: a reviewer needs to see the
    observation, not just the conclusion.
    """

    target_id: str
    app: str
    module: str
    description: str = ""
    stack: tuple[str, ...] = ()
    observations: list[Observation] = field(default_factory=list)
    #: fact -> the signals that fired
    facts: dict[str, bool] = field(default_factory=dict)
    fact_provenance: dict[str, list[str]] = field(default_factory=dict)
    #: Intended/known vulnerability classes from the app's own docs. This is
    #: the app author's claim, not our judgement, and it is the comparison
    #: point for the annotation — not a substitute for it.
    documented_classes: tuple[str, ...] = ()
    source_url: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["observations"] = [o.as_dict() for o in self.observations]
        d["stack"] = list(self.stack)
        d["documented_classes"] = list(self.documented_classes)
        return d

    def to_spec(self):
        """Convert to an annotatable :class:`~tinyforge.labelset.TargetSpec`.

        Only the facts carry over. Nothing about which techniques apply is
        pre-filled, because the point of the exercise is to have a human
        decide that independently.
        """
        from .labelset import TargetSpec

        return TargetSpec(
            target_id=self.target_id,
            description=self.description or f"{self.app} / {self.module}",
            observed_facts={k: v for k, v in self.facts.items() if v},
            attempted_tools=(),
            tool_techniques={},
            evidence_digests={},
            narrative="",
            discovered={},
        )


def infer_facts(observations: Sequence[Observation]) -> tuple[dict[str, bool], dict[str, list[str]]]:
    """Derive applicability facts from raw observations.

    Returns ``(facts, provenance)``. A fact is set only when at least one
    signal matches. Nothing is inferred from absence — an unobserved signal
    leaves the fact unset, which is what keeps a sparse target from being
    treated as if we knew it was clean.
    """
    # Only the observation *values* form the blob. Including `kind` would
    # let the literal "source" satisfy the bare `rce` pattern (sou-rce),
    # manufacturing a phantom code-execution test on every observation.
    # Signal patterns are matched against evidence, never against our own
    # vocabulary for describing it.
    blob = "\n".join(obs.value for obs in observations).lower()

    facts: dict[str, bool] = {}
    provenance: dict[str, list[str]] = {}

    for fact, signals in FACT_SIGNALS.items():
        hits: list[str] = []
        for pattern, why in signals:
            if re.search(pattern, blob, re.IGNORECASE):
                hits.append(why)
        if hits:
            facts[fact] = True
            provenance[fact] = hits
        else:
            facts[fact] = False

    return facts, provenance


def build_target(
    target_id: str,
    app: str,
    module: str,
    observations: Sequence[Observation],
    *,
    description: str = "",
    stack: Sequence[str] = (),
    documented_classes: Sequence[str] = (),
    source_url: str = "",
) -> ReconTarget:
    """Assemble a :class:`ReconTarget`, inferring facts from observations."""
    facts, provenance = infer_facts(observations)
    return ReconTarget(
        target_id=target_id,
        app=app,
        module=module,
        description=description,
        stack=tuple(stack),
        observations=list(observations),
        facts=facts,
        fact_provenance=provenance,
        documented_classes=tuple(documented_classes),
        source_url=source_url,
    )


def save_targets(path: str, targets: Sequence[ReconTarget]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([t.as_dict() for t in targets], fh, indent=2)


def load_targets(path: str) -> list[ReconTarget]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    out: list[ReconTarget] = []
    for r in raw:
        obs = [Observation(**o) for o in r.get("observations", [])]
        out.append(
            ReconTarget(
                target_id=r["target_id"],
                app=r["app"],
                module=r["module"],
                description=r.get("description", ""),
                stack=tuple(r.get("stack", ())),
                observations=obs,
                facts=r.get("facts", {}),
                fact_provenance=r.get("fact_provenance", {}),
                documented_classes=tuple(r.get("documented_classes", ())),
                source_url=r.get("source_url", ""),
            )
        )
    return out
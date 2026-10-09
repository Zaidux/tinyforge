"""Applicability: deciding which techniques *should* have been tried.

Research identified this as the true bottleneck, not data volume. From the
data-gap analysis: *"The bottleneck is the applicability function — deciding,
per task, which of 30 techniques should have been tried. Get that wrong and
every label is noise."*

The failure it prevents is specific and severe. Without an applicability
gate, a trajectory that tested SQLi but never tested XXE looks exactly like
one that tested neither. The scorer then learns to flag everything, because
"missing" is always true relative to the full technique list.

## Why this is deterministic rather than learned

Applicability is a **property of the target**, observable before any
scanning: it runs WordPress, it has a GraphQL endpoint, it accepts file
uploads. It is not a judgement about attacker intent, so there is nothing
here for a language model to add and a learned component would only obscure
the reasoning.

Deliberately conservative in two directions:

* **No wildcards.** A technique fires only when its condition is explicitly
  satisfied by declared profile facts. Unknown facts produce no signal,
  which means the default is "not applicable" — so an under-specified
  profile produces fewer gaps, never a flood of them.
* **Every decision is explainable.** :func:`explain` returns the chain of
  facts that produced each applicable technique. A coverage claim that
  cannot be traced to an observable property is not a claim worth acting on.

## The asymmetry, stated plainly

Recall PRISM's finding (arXiv:2606.09078): false negatives slow exploration,
false positives actively steer selection toward wrong answers. This module
is therefore biased toward *under*-flagging, and that bias is intentional.
A missed gap costs a little coverage; a spurious one derails an
investigation and trains a scorer that cannot be trusted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

__all__ = [
    "TargetProfile",
    "Technique",
    "CATALOGUE",
    "applicable",
    "explain",
    "coverage_matrix",
    "profile_from_observations",
]


@dataclass(frozen=True)
class Technique:
    """One testable technique and the conditions that make it applicable.

    ``requires`` is an AND over predicate names. Predicates read the target
    profile. An unknown predicate never fires, so adding a technique without
    wiring its predicate is safe: it simply stays inapplicable.
    """

    id: str
    label: str
    requires: tuple[str, ...]
    #: Free-form category, useful for grouping in reports.
    category: str = "general"
    #: Tool names that are the conventional means of testing it.
    tools: tuple[str, ...] = ()
    cwe: str = ""
    owasp_api: str = ""
    owasp_top10_2025: str = ""


def _has_any(facts: Mapping[str, object], key: str) -> bool:
    value = facts.get(key)
    if isinstance(value, (list, tuple, set, frozenset)):
        return bool(value)
    return bool(value)


#: The technique catalogue. Sources are cited in DATA_SPEC.md; identifiers
#: follow WSTG v4.2 numbering where a mapping exists.
#:
#: Kept small on purpose. The full crosswalk (141 WSTG tests, 30 PortSwigger
#: topics, 25 CWEs) is ~200 labels, which is far too many for a 5-20M scorer
#: to learn reliably. 15 leaves is where a signal is still identifiable.
CATALOGUE: tuple[Technique, ...] = (
    # ── Always applicable to a web target ──
    Technique("recon", "Subdomain and endpoint discovery",
              requires=(), category="recon",
              tools=("subfinder", "httpx", "waybackurls", "katana"),
              owasp_top10_2025="A01:2025"),
    Technique("port_scan", "Service and port discovery",
              requires=("has_network_surface",), category="recon",
              tools=("nmap", "naabu")),
    Technique("config_review", "Security misconfiguration review",
              requires=(), category="web",
              tools=("nikto", "nuclei"), owasp_top10_2025="A02:2025"),
    Technique("auth_session", "Authentication and session handling",
              requires=("has_login",), category="auth",
              tools=("curl",), owasp_top10_2025="A07:2025"),

    # ── Conditional on observed surface ──
    Technique("sql_injection", "SQL injection",
              requires=("has_relational_db",), category="injection",
              tools=("sqlmap",), cwe="CWE-89",
              owasp_top10_2025="A05:2025"),
    Technique("nosql_injection", "NoSQL injection",
              requires=("uses_nosql",), category="injection",
              tools=("curl",), cwe="CWE-943"),
    Technique("xss_reflected", "Reflected XSS",
              requires=("has_reflected_input",), category="web",
              tools=("dalfox",), cwe="CWE-79",
              owasp_top10_2025="A05:2025"),
    Technique("xss_stored", "Stored XSS",
              requires=("has_persisted_input",), category="web",
              tools=("dalfox",), cwe="CWE-79"),
    Technique("ssrf", "Server-side request forgery",
              requires=("makes_server_requests",), category="web",
              tools=("curl",), cwe="CWE-918",
              owasp_api="API7:2023"),
    Technique("xxe", "XML external entity processing",
              requires=("accepts_xml",), category="injection",
              tools=("xxeinjector",), cwe="CWE-611"),
    Technique("csrf", "Cross-site request forgery",
              requires=("has_session_auth",), category="web",
              tools=("curl",), cwe="CWE-352"),
    Technique("idor", "Insecure direct object reference",
              requires=("has_object_ids",), category="authz",
              tools=("curl", "ffuf"), cwe="CWE-639",
              owasp_api="API1:2023", owasp_top10_2025="A01:2025"),
    Technique("bfa", "Broken function-level authorization",
              requires=("has_role_model",), category="authz",
              tools=("curl",), cwe="CWE-862",
              owasp_api="API5:2023", owasp_top10_2025="A01:2025"),
    Technique("file_upload", "Unrestricted file upload",
              requires=("has_upload",), category="web",
              tools=("curl",), cwe="CWE-434",
              owasp_api="API8:2023"),
    Technique("ssti", "Server-side template injection",
              requires=("has_templating",), category="injection",
              tools=("tplmap",), cwe="CWE-1336"),
    Technique("deserialization", "Unsafe deserialization",
              requires=("has_deserialization",), category="injection",
              tools=("ysoserial",), cwe="CWE-502"),
    Technique("jwt", "JWT handling weaknesses",
              requires=("uses_jwt",), category="auth",
              tools=("jwt_tool",), owasp_top10_2025="A07:2025"),
    Technique("cors", "CORS misconfiguration",
              requires=("has_cors",), category="web",
              tools=("curl",)),
    Technique("race_condition", "Race conditions",
              requires=("has_state_transitions",), category="logic",
              tools=("curl",)),
    Technique("business_logic", "Business logic flaws",
              requires=("has_commerce",), category="logic",
              tools=()),

    # ── Code-execution class ──
    # Added after the AutoPenBench gate (arXiv:2410.03225). Five of the
    # twelve exploits named in its real-world CVE tasks imply remote code
    # execution — geoserver_unauth_rce, spring4shell, log4shell_scanner,
    # bludit_upload_images_exec, apache_druid_js_rce — and the catalogue had
    # no technique for it. `config_review` was the nearest bucket and it is
    # the wrong claim: "a RCE exists here" is a distinct testable assertion
    # from "this host is misconfigured". Conflating them flags every
    # CVE-bearing target, which is the flag-everything failure this whole
    # module exists to prevent.
    Technique("command_injection", "OS command injection",
              requires=("has_shell_output",), category="execution",
              tools=("commix",), cwe="CWE-78",
              owasp_top10_2025="A05:2025"),
    Technique("rce", "Remote code execution",
              requires=("has_code_execution_path",), category="execution",
              tools=("metasploit",), cwe="CWE-94",
              owasp_top10_2025="A05:2025"),
    Technique("path_traversal", "Path traversal / arbitrary file read",
              requires=("has_file_access",), category="file",
              tools=("ffuf",), cwe="CWE-22",
              owasp_top10_2025="A01:2025"),
)


@dataclass
class TargetProfile:
    """Observable facts about a target.

    Every field is something discoverable from recon — stack headers, an
    endpoint inventory, a login form. Nothing here is attacker intent.
    """

    name: str = "target"
    kind: str = "web"
    #: Observable facts consumed by technique predicates.
    facts: dict[str, object] = field(default_factory=dict)

    def with_facts(self, **facts) -> "TargetProfile":
        merged = dict(self.facts)
        merged.update(facts)
        return TargetProfile(self.name, self.kind, merged)

    @property
    def tools(self) -> tuple[str, ...]:
        """Conventional tools for the applicable techniques."""
        techs = applicable(self)
        out: list[str] = []
        for t in CATALOGUE:
            if t.id in techs:
                out.extend(t.tools)
        return tuple(dict.fromkeys(out))


def _predicate_registry() -> dict[str, Callable[[Mapping[str, object]], bool]]:
    return {
        "has_network_surface": lambda f: _has_any(f, "has_network_surface"),
        "has_login": lambda f: _has_any(f, "has_login"),
        "has_relational_db": lambda f: _has_any(f, "has_relational_db"),
        "uses_nosql": lambda f: _has_any(f, "uses_nosql"),
        "has_reflected_input": lambda f: _has_any(f, "has_reflected_input"),
        "has_persisted_input": lambda f: _has_any(f, "has_persisted_input"),
        "makes_server_requests": lambda f: _has_any(f, "makes_server_requests"),
        "accepts_xml": lambda f: _has_any(f, "accepts_xml"),
        "has_session_auth": lambda f: _has_any(f, "has_session_auth"),
        "has_object_ids": lambda f: _has_any(f, "has_object_ids"),
        "has_role_model": lambda f: _has_any(f, "has_role_model"),
        "has_upload": lambda f: _has_any(f, "has_upload"),
        "has_templating": lambda f: _has_any(f, "has_templating"),
        "has_deserialization": lambda f: _has_any(f, "has_deserialization"),
        "uses_jwt": lambda f: _has_any(f, "uses_jwt"),
        "has_cors": lambda f: _has_any(f, "has_cors"),
        "has_state_transitions": lambda f: _has_any(f, "has_state_transitions"),
        "has_commerce": lambda f: _has_any(f, "has_commerce"),
        "has_shell_output": lambda f: _has_any(f, "has_shell_output"),
        "has_code_execution_path": lambda f: _has_any(f, "has_code_execution_path"),
        "has_file_access": lambda f: _has_any(f, "has_file_access"),
    }


def applicable(profile: TargetProfile) -> set[str]:
    """Technique ids that genuinely apply to *profile*.

    Unknown predicates never fire. That is the conservative default and it
    matters: an under-specified profile produces fewer flagged gaps, not
    more, which is the correct direction given false positives are the
    damaging error.
    """
    registry = _predicate_registry()
    facts = profile.facts
    out: set[str] = set()
    for tech in CATALOGUE:
        if not tech.requires:
            out.add(tech.id)  # unconditional
            continue
        if all(
            (pred := registry.get(name)) is not None and pred(facts)
            for name in tech.requires
        ):
            out.add(tech.id)
    return out


def explain(profile: TargetProfile) -> dict[str, list[str]]:
    """Map each applicable technique to the facts that justify it.

    A coverage claim that cannot be traced to an observable property is not
    a claim worth acting on, so this is part of the public API rather than a
    debugging aid.
    """
    registry = _predicate_registry()
    facts = profile.facts
    out: dict[str, list[str]] = {}
    for tech in CATALOGUE:
        if not tech.requires:
            out[tech.id] = ["unconditional"]
            continue
        reasons = [
            f"{name}={facts.get(name)!r}"
            for name in tech.requires
            if (pred := registry.get(name)) is not None and pred(facts)
        ]
        if reasons:
            out[tech.id] = reasons
    return out


def expected_tools(profile: TargetProfile) -> tuple[str, ...]:
    return profile.tools


def coverage_matrix(
    profile: TargetProfile, attempted: Sequence[str]
) -> dict[str, object]:
    """Which applicable techniques went untested.

    Returns both the covered set and the reasoning for each gap so a caller
    can decide whether the signal is trustworthy.
    """
    techs = applicable(profile)
    tools_used = set(attempted)
    covered, gaps = set(), {}
    reasons = explain(profile)

    for tech in CATALOGUE:
        if tech.id not in techs:
            continue
        indicators = set(tech.tools) or {tech.id}
        if indicators & tools_used:
            covered.add(tech.id)
        else:
            gaps[tech.id] = {
                "label": tech.label,
                "why_applicable": reasons.get(tech.id, []),
                "conventional_tools": list(tech.tools),
            }

    return {
        "applicable": sorted(techs),
        "covered": sorted(covered),
        "gaps": gaps,
        "coverage": round(len(covered) / len(techs), 4) if techs else 0.0,
    }


#: Canned profiles for synthetic generation. Each is a plausible real-world
#: shape; the facts are the observable evidence that makes a technique
#: applicable, not assumptions about the target.
PRESET_PROFILES: tuple[TargetProfile, ...] = (
    TargetProfile("ecommerce_web", facts={
        "has_network_surface": True, "has_login": True,
        "has_relational_db": True, "has_reflected_input": True,
        "has_persisted_input": True, "has_object_ids": True,
        "has_session_auth": True, "has_cors": True, "has_commerce": True,
        "has_file_access": True, "has_shell_output": True,
    }),
    TargetProfile("rest_api_jwt", facts={
        "has_network_surface": True, "uses_jwt": True,
        "has_object_ids": True, "has_role_model": True,
        "has_relational_db": True, "makes_server_requests": True,
        "has_shell_output": True,
    }),
    TargetProfile("file_upload_service", facts={
        "has_network_surface": True, "has_upload": True,
        "makes_server_requests": True, "accepts_xml": True,
        "has_templating": True, "has_login": True,
        "has_deserialization": True, "has_file_access": True,
        "has_code_execution_path": True,
    }),
    TargetProfile("soap_legacy", facts={
        "has_network_surface": True, "accepts_xml": True,
        "has_deserialization": True, "has_login": True,
        "has_relational_db": True, "has_code_execution_path": True,
    }),
    TargetProfile("nosql_api", facts={
        "has_network_surface": True, "uses_nosql": True,
        "has_object_ids": True, "has_login": True,
    }),
    TargetProfile("vulnerable_web_service", facts={
        # Models the AutoPenBench real-world CVE shape: a dated, exposed
        # product version. This is where RCE becomes applicable.
        "has_network_surface": True, "has_login": True,
        "has_file_access": True, "has_shell_output": True,
        "has_code_execution_path": True, "has_reflected_input": True,
    }),
    TargetProfile("minimal_static", facts={}),
)


def profile_from_observations(
    observations: Mapping[str, object], *, name: str = "target"
) -> TargetProfile:
    """Build a profile from raw recon output.

    Anything unrecognised is dropped rather than guessed. Guessing is what
    produces phantom gaps.
    """
    known = set(_predicate_registry())
    facts = {k: v for k, v in observations.items() if k in known and _has_any(observations, k)}
    return TargetProfile(name=name, facts=facts)
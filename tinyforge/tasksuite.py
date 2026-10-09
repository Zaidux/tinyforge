"""Synthetic task suite for validating the experiment harness.

Purpose is narrow and worth stating plainly: **this does not replace real
evaluation data.** It exists so the runner, judges, and paired statistics can
be exercised end-to-end before any real corpus is assembled — and so a bug in
the harness shows up as a failing test rather than as a surprising result
three weeks into an experiment.

Once real data lands, :func:`load_tasks` reads the same :class:`Task` schema
from JSON, so the harness code is unchanged.

## Ground truth design

Each synthetic task carries a `ground_truth_coverage` field naming the
techniques a *complete* investigation would touch. The scorer is measured
on whether it flags the ones the trajectory omitted. Because the taxonomy
and the trajectory are both generated here, the label is exact by
construction — which is the point: it tests the machinery, not the
taxonomy's realism.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from typing import Callable, Sequence

from .applicability import (
    PRESET_PROFILES,
    TargetProfile,
    applicable,
    coverage_matrix,
)
from .experiments import Task

__all__ = [
    "TECHNIQUES",
    "TOOLS_BY_TECHNIQUE",
    "SyntheticCase",
    "generate_cases",
    "to_tasks",
    "load_tasks",
    "write_tasks",
]


#: Legacy flat technique map, retained so existing serialised cases still
#: load. New generation uses the applicability catalogue instead — see
#: :func:`generate_cases`.
TECHNIQUES: dict[str, tuple[str, ...]] = {
    "recon": ("subfinder", "httpx", "waybackurls"),
    "port_scan": ("nmap", "naabu"),
    "directory_enum": ("ffuf", "feroxbuster"),
    "sql_injection": ("sqlmap",),
    "xss_reflected": ("dalfox",),
    "xss_stored": ("dalfox", "burp"),
    "ssrf": ("ffuf",),
    "xxe": ("xxeinjector",),
    "auth_bypass": ("curl",),
    "idor": ("curl", "ffuf"),
    "file_upload": ("curl",),
    "subdomain_takeover": ("nuclei", "subfinder"),
}

#: Tools an agent might plausibly have available.
_ALL_TOOLS: tuple[str, ...] = tuple(
    sorted({t for tools in TECHNIQUES.values() for t in tools})
)


@dataclass
class SyntheticCase:
    """One generated case, before conversion into a runnable :class:`Task`."""

    case_id: str
    target_description: str
    attempted_tools: tuple[str, ...]
    available_tools: tuple[str, ...]
    ground_truth_coverage: tuple[str, ...]
    technique_findings: tuple[str, ...] = ()
    ungrounded_claim: str = ""
    difficulty: str = "easy"
    #: Facts that produced ``ground_truth_coverage``. Persisted so a label
    #: can be re-derived and audited without re-running generation.
    profile_facts: dict = field(default_factory=dict)

    @property
    def missing_techniques(self) -> tuple[str, ...]:
        """Untested applicable techniques, derived from the applicability gate.

        This no longer consults the legacy :data:`TECHNIQUES` map. Gaps are
        exactly ``applicable(profile) - covered(profile, attempted)``, which
        is what makes "you never tried X" a defensible claim rather than an
        artefact of an invented list.
        """
        profile = TargetProfile(self.target_description, facts=dict(self.profile_facts))
        matrix = coverage_matrix(profile, self.attempted_tools)
        return tuple(matrix["gaps"].keys())

    def as_dict(self) -> dict:
        d = asdict(self)
        d["missing_techniques"] = list(self.missing_techniques)
        return d

#: Short, constrained task briefs. Open-ended phrasing ("describe the steps
#: you would take") is deliberately avoided: both available oracle models
#: burned their entire token budget on reasoning and returned no content.
#: Constrained prompts are the only reliable shape, and oracle.py now flags
#: the truncation case explicitly.
_BRIEFS = {
    "ecommerce_web": (
        "An e-commerce site has a login form, a product search box, a cart, "
        "and a support page. It runs on a relational database.\n"
        "List exactly 4 distinct vulnerability classes you would test, one per "
        "line. For each, name the single tool you would use. "
        "Do not include recon or scanning steps."
    ),
    "rest_api_jwt": (
        "A REST API authenticates with JWT. Endpoints take numeric object IDs, "
        "roles differ between accounts, and it proxies outbound requests. "
        "It queries a relational database.\n"
        "List exactly 4 distinct vulnerability classes you would test, one per "
        "line. For each, name the single tool you would use. "
        "Do not include recon or scanning steps."
    ),
    "file_upload_service": (
        "A document conversion service accepts file uploads, parses XML, uses a "
        "server-side template engine, fetches remote URLs, and requires login.\n"
        "List exactly 4 distinct vulnerability classes you would test, one per "
        "line. For each, name the single tool you would use. "
        "Do not include recon or scanning steps."
    ),
    "soap_legacy": (
        "A legacy SOAP service accepts XML, deserializes objects, uses a "
        "relational database, and requires login.\n"
        "List exactly 4 distinct vulnerability classes you would test, one per "
        "line. For each, name the single tool you would use. "
        "Do not include recon or scanning steps."
    ),
    "nosql_api": (
        "An API backed by a document database returns records by numeric ID and "
        "has a login page.\n"
        "List exactly 3 distinct vulnerability classes you would test, one per "
        "line. For each, name the single tool you would use. "
        "Do not include recon or scanning steps."
    ),
    "minimal_static": (
        "A static marketing site with no login, no database, and no forms.\n"
        "List exactly 2 distinct vulnerability classes you would test, one per "
        "line. For each, name the single tool you would use. "
        "Do not include recon or scanning steps."
    ),
}


def generate_cases(
    n: int = 40, *, seed: int = 7, coverage_bias: float = 0.55
) -> list[SyntheticCase]:
    """Generate *n* synthetic cases gated by the applicability function.

    Ground truth is now ``applicable(profile)`` rather than an invented list,
    so a "gap" always traces to an observable fact about the target.

    ``coverage_bias`` is the probability that any given applicable technique
    ends up covered. Below 0.5 yields mostly-blind-spot cases; near 1.0
    yields mostly-complete ones. **Both directions are required** — a suite
    with only positive cases trains a scorer that flags everything.
    """
    rng = random.Random(seed)
    cases: list[SyntheticCase] = []

    for i in range(n):
        profile = PRESET_PROFILES[rng.randrange(len(PRESET_PROFILES))]
        techs = sorted(applicable(profile))
        available = profile.tools

        attempted: list[str] = []
        for tech in techs:
            if rng.random() < coverage_bias:
                indicators = [t for t in available
                              if t in _TOOLS_FOR(tech)]
                if indicators:
                    attempted.append(rng.choice(indicators))
        attempted = list(dict.fromkeys(attempted))

        findings = tuple(
            t for t in techs
            if set(_TOOLS_FOR(t)) & set(attempted)
        )

        ungrounded = ""
        if rng.random() < 0.35 and findings:
            claimed = rng.choice(findings)
            ungrounded = (
                f"I confirmed a {claimed.replace('_', ' ')} vulnerability and "
                f"verified it can be exploited remotely."
            )

        cases.append(
            SyntheticCase(
                case_id=f"syn-{i:04d}",
                target_description=profile.name,
                attempted_tools=tuple(attempted),
                available_tools=tuple(available),
                ground_truth_coverage=tuple(techs),
                technique_findings=findings,
                ungrounded_claim=ungrounded,
                difficulty=rng.choice(["easy", "medium", "hard"]),
                profile_facts=dict(profile.facts),
            )
        )

    return cases


_TOOL_CACHE: dict[str, tuple[str, ...]] = {}


def _TOOLS_FOR(tech_id: str) -> tuple[str, ...]:
    """Conventional tools for a technique id, memoised."""
    if not _TOOL_CACHE:
        from .applicability import CATALOGUE

        for t in CATALOGUE:
            _TOOL_CACHE[t.id] = t.tools
    return _TOOL_CACHE.get(tech_id, ())


def _default_judge(case: SyntheticCase) -> Callable[[str], bool]:
    """Judge: did the output address the case's missing techniques?"""
    missing = case.missing_techniques

    def judge(text: str) -> bool:
        if not missing:
            # Nothing was missing; the judge should not pass or fail on
            # technique coverage. Treat a substantive answer as a pass.
            return len(text.strip()) > 80
        lowered = text.lower()
        hits = 0
        for tech in missing:
            # Accept either the technique name or any of its tool markers.
            if tech.replace("_", " ") in lowered or tech.replace("_", "") in lowered:
                hits += 1
            elif any(t.lower() in lowered for t in TECHNIQUES.get(tech, ())):
                hits += 1
        return hits >= max(1, len(missing) // 2)

    return judge


def to_tasks(cases: Sequence[SyntheticCase]) -> list[Task]:
    """Convert synthetic cases into runnable :class:`Task` objects."""
    tasks: list[Task] = []
    for case in cases:
        brief = _BRIEFS.get(
            case.target_description,
            "List exactly 3 distinct vulnerability classes you would test, one "
            "per line, naming the tool for each. Do not include recon steps.",
        )
        notes = ", ".join(case.technique_findings)
        if case.ungrounded_claim:
            notes = f"{notes}\n{case.ungrounded_claim}".strip()

        tasks.append(
            Task(
                task_id=case.case_id,
                prompt=brief,
                judge=_default_judge(case),
                available_tools=case.available_tools,
                required_tools=(),
                techniques={k: list(v) for k, v in TECHNIQUES.items()},
                reference_notes=notes,
                metadata={
                    "ground_truth_coverage": list(case.ground_truth_coverage),
                    "missing_techniques": list(case.missing_techniques),
                    "ungrounded_claim": case.ungrounded_claim,
                    "difficulty": case.difficulty,
                    "profile_facts": case.profile_facts,
                    "synthetic": True,
                },
            )
        )
    return tasks


def write_tasks(cases: Sequence[SyntheticCase], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([c.as_dict() for c in cases], fh, indent=2)


def load_tasks(path: str) -> list[tuple[Task, SyntheticCase]]:
    """Load persisted cases back into ``(Task, SyntheticCase)`` pairs.

    Real-corpus loaders will follow this shape so the harness is unchanged
    when genuine data replaces the synthetic set.
    """
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    cases = [
        SyntheticCase(
            case_id=r["case_id"],
            target_description=r["target_description"],
            attempted_tools=tuple(r["attempted_tools"]),
            available_tools=tuple(r["available_tools"]),
            ground_truth_coverage=tuple(r["ground_truth_coverage"]),
            technique_findings=tuple(r.get("technique_findings", ())),
            ungrounded_claim=r.get("ungrounded_claim", ""),
            difficulty=r.get("difficulty", "easy"),
        )
        for r in raw
    ]
    return list(zip(to_tasks(cases), cases))
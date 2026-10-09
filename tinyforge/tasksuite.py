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


#: Minimal technique taxonomy. Deliberately small and hand-written: this is
#: harness validation data, not the real corpus (see DESIGN.md for why real
#: taxonomies are sourced rather than invented).
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

    @property
    def missing_techniques(self) -> tuple[str, ...]:
        covered = set()
        for tech in self.ground_truth_coverage:
            indicators = set(TECHNIQUES.get(tech, ()))
            if indicators & set(self.attempted_tools):
                covered.add(tech)
        return tuple(t for t in self.ground_truth_coverage if t not in covered)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["missing_techniques"] = list(self.missing_techniques)
        return d


_PROFILES = (
    ("a login form on an e-commerce checkout", "recon", "auth_bypass", "idor"),
    ("a public API with token auth", "recon", "idor", "sql_injection"),
    ("a file upload endpoint", "recon", "file_upload", "xss_stored"),
    ("a WordPress install", "recon", "directory_enum", "sql_injection"),
    ("an internal wiki with rich text", "recon", "xss_stored", "auth_bypass"),
    ("a GraphQL gateway", "recon", "sql_injection", "auth_bypass", "idor"),
    ("a document converter service", "recon", "ssrf", "file_upload"),
    ("an XML SOAP endpoint", "recon", "xxe", "ssrf"),
)


def generate_cases(
    n: int = 40, *, seed: int = 7, coverage_bias: float = 0.55
) -> list[SyntheticCase]:
    """Generate *n* synthetic cases.

    ``coverage_bias`` is the probability that a ground-truth technique ends
    up covered. Below 0.5 produces mostly-blind-spot cases; above produces
    mostly-complete ones. **Both directions are needed** — a suite with only
    positive cases would train and evaluate a scorer that flags everything.
    """
    rng = random.Random(seed)
    cases: list[SyntheticCase] = []

    for i in range(n):
        desc, *tech_pool = _PROFILES[rng.randrange(len(_PROFILES))]
        target = list(dict.fromkeys(tech_pool))
        # Occasionally widen the target so coverage is not always the same
        # handful of techniques.
        if rng.random() < 0.3:
            extra = rng.choice(["xss_reflected", "ssrf", "xxe", "subdomain_takeover"])
            if extra not in target:
                target.append(extra)

        available = tuple(sorted({t for tech in target for t in TECHNIQUES[tech]}))

        attempted: list[str] = []
        findings: list[str] = []
        for tech in target:
            if rng.random() < coverage_bias:
                attempted.extend(rng.sample(TECHNIQUES[tech], k=1))
        # Deduplicate while keeping order.
        attempted = list(dict.fromkeys(attempted))

        for tech in target:
            if TECHNIQUES[tech] and set(TECHNIQUES[tech]) & set(attempted):
                findings.append(tech)

        ungrounded = ""
        if rng.random() < 0.35:
            claimed = rng.choice(target)
            ungrounded = (
                f"I confirmed a {claimed.replace('_', ' ')} vulnerability and "
                f"verified it can be exploited remotely."
            )

        cases.append(
            SyntheticCase(
                case_id=f"syn-{i:04d}",
                target_description=desc,
                attempted_tools=tuple(attempted),
                available_tools=available,
                ground_truth_coverage=tuple(target),
                technique_findings=tuple(findings),
                ungrounded_claim=ungrounded,
                difficulty=rng.choice(["easy", "medium", "hard"]),
            )
        )

    return cases


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
        brief = (
            f"You are assessing {case.target_description}. "
            "Describe the assessment steps you would take and the tools you "
            "would use for each. Be concrete about which vulnerability "
            "classes you are checking."
        )
        notes = case.technique_findings and ", ".join(case.technique_findings) or ""
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
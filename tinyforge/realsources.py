"""Real target sources: Juice Shop and OWASP BenchmarkJava.

## Why these two and not the others

A survey of twelve deliberately-vulnerable applications found these two
uniquely useful, for a reason specific to our problem.

**OWASP BenchmarkJava is the only source of *negative* ground truth.**
Its ``expectedresults-1.2.csv`` encodes, per test case:

```
BenchmarkTest00001,pathtraver,true,22      <- CWE-22, IS vulnerable
BenchmarkTest00568,sqli,false,89           <- CWE-89, is NOT vulnerable
```

1,415 true and 1,325 false. Everything else — Juice Shop, DVWA, WebGoat,
Mutillidae — describes what *is* vulnerable and has no equivalent "this one
looks vulnerable and is not" label.

That matters enormously here. A coverage checker's failure mode is
over-flagging, and you cannot measure whether a checker avoids over-flagging
against a corpus where everything is vulnerable. A benchmark where the
majority class is "the vulnerability class applies but this case is safe"
is the correct adversarial test.

**Juice Shop supplies breadth plus real incidental CVEs.** 104 challenges
across 16 categories, and — uniquely — it ships genuinely outdated
dependencies (``jsonwebtoken@0.4.0``, ``multer@1.4.5-lts.1``,
``sanitize-html@1.4.2``) alongside its intentional challenges. So the checker
can be scored on whether it separates *intentional challenge* from *pinned
vulnerable dependency*, which our RCE predicate needs to handle.

## What is deliberately NOT done here

Neither application is executed, and no request is sent to anything. Both
sources are parsed from their own published metadata, which is a form of
static observation and is honest about it.

The consequence is stated plainly in
:meth:`BenchmarkSource.negative_cases`: without running the app we cannot
confirm a case is genuinely non-vulnerable, so those labels are treated as
*claimed* rather than verified. Benchmark's own authors state the false cases
are non-vulnerable, and we take that at face value for a controlled
benchmark — but it is a dependency, not a measurement.
"""

from __future__ import annotations

import csv
import io
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "BenchmarkCase",
    "BenchmarkSource",
    "JuiceShopChallenge",
    "JuiceShopSource",
    "CWE_TECHNIQUE",
    "_scalar",
    "fetch",
]

_UA = {"User-Agent": "tinyforge"}

#: CWE -> our technique id. Reuses the mapping in :mod:`tinyforge.nvd` so
#: there is exactly one place where a CWE becomes a technique label.
from .nvd import CWE_TECHNIQUE


def fetch(url: str, timeout: int = 60) -> str:
    """Fetch a URL, raising with the status on failure."""
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        return fh.read().decode("utf-8", "replace")


# ── OWASP BenchmarkJava ────────────────────────────────────────────────────

_BENCHMARK_CSV = (
    "https://raw.githubusercontent.com/OWASP-Benchmark/"
    "BenchmarkJava/master/expectedresults-1.2.csv"
)


@dataclass
class BenchmarkCase:
    """One Benchmark test case with its ground-truth label."""

    case_id: str
    category: str
    #: True when the case genuinely contains the vulnerability.
    is_vulnerable: bool
    cwe: int

    @property
    def technique(self) -> str | None:
        return CWE_TECHNIQUE.get(f"CWE-{self.cwe}")

    def as_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "is_vulnerable": self.is_vulnerable,
            "cwe": self.cwe,
            "technique": self.technique,
        }


@dataclass
class BenchmarkSource:
    """OWASP BenchmarkJava ground truth."""

    url: str = _BENCHMARK_CSV
    cases: list[BenchmarkCase] = field(default_factory=list)

    @classmethod
    def fetch(cls, url: str = _BENCHMARK_CSV) -> "BenchmarkSource":
        return cls(url=url, cases=cls._parse_rows(fetch(url)))

    @staticmethod
    def _parse_rows(text: str) -> list[BenchmarkCase]:
        rows = list(csv.reader(io.StringIO(text)))
        cases: list[BenchmarkCase] = []
        for r in rows[1:]:
            if len(r) < 4 or not r[0].startswith("BenchmarkTest"):
                continue
            try:
                cases.append(
                    BenchmarkCase(
                        case_id=r[0].strip(),
                        category=r[1].strip(),
                        is_vulnerable=r[2].strip().lower() == "true",
                        cwe=int(r[3].strip()),
                    )
                )
            except ValueError:
                continue
        return cases

    def vulnerable(self) -> list[BenchmarkCase]:
        return [c for c in self.cases if c.is_vulnerable]

    def negative_cases(self) -> list[BenchmarkCase]:
        """Cases where the vulnerability class applies but the case is safe.

        **These labels are claimed by Benchmark's authors, not verified
        here** — the application was never executed. Treating an unverified
        label as measured would be exactly the sin RESULTS.md documents, so
        every downstream claim must carry that caveat.

        This is the only set in the project that exercises "looks vulnerable,
        is not", and therefore the only set that can measure whether the
        checker over-flags.
        """
        return [c for c in self.cases if not c.is_vulnerable]

    def by_technique(self) -> dict[str, list[BenchmarkCase]]:
        out: dict[str, list[BenchmarkCase]] = {}
        for c in self.cases:
            tech = c.technique
            if tech:
                out.setdefault(tech, []).append(c)
        return out

    def summary(self) -> dict:
        by_tech = self.by_technique()
        neg_by_tech: dict[str, int] = {}
        pos_by_tech: dict[str, int] = {}
        for tech, cases in by_tech.items():
            neg_by_tech[tech] = sum(1 for c in cases if not c.is_vulnerable)
            pos_by_tech[tech] = sum(1 for c in cases if c.is_vulnerable)
        return {
            "source": "OWASP BenchmarkJava expectedresults-1.2.csv",
            "url": self.url,
            "total": len(self.cases),
            "vulnerable": len(self.vulnerable()),
            "negative": len(self.negative_cases()),
            "techniques": sorted(by_tech),
            "negative_per_technique": {
                k: v for k, v in sorted(neg_by_tech.items()) if v
            },
            "positive_per_technique": {
                k: v for k, v in sorted(pos_by_tech.items()) if v
            },
            "caveat": (
                "labels are the benchmark authors' claim; the application was "
                "not executed here, so negatives are unverified"
            ),
        }


# ── OWASP Juice Shop ───────────────────────────────────────────────────────

_JUICESHOP_CHALLENGES = (
    "https://raw.githubusercontent.com/juice-shop/juice-shop/"
    "master/data/static/challenges.yml"
)
_JUICESHOP_PKG = (
    "https://raw.githubusercontent.com/juice-shop/juice-shop/master/package.json"
)

#: Juice Shop category -> our technique ids. This is the app author's own
#: categorisation, not our judgement; it is recorded so an adjudicator has a
#: comparison point rather than being handed our answer.
_JUICESHOP_CATEGORY_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "Injection": ("sql_injection", "nosql_injection"),
    "XSS": ("xss_reflected", "xss_stored"),
    "XXE": ("xxe",),
    "Insecure Deserialization": ("deserialization", "rce"),
    "Broken Access Control": ("idor", "bfa"),
    "Broken Authentication": ("auth_session", "jwt"),
    "Cryptographic Issues": ("auth_session", "jwt"),
    "Sensitive Data Exposure": ("config_review", "idor"),
    "Security Misconfiguration": ("config_review",),
    "Unvalidated Redirects": ("config_review",),
}


@dataclass
class JuiceShopChallenge:
    """One Juice Shop challenge."""

    name: str
    category: str
    description: str
    difficulty: int
    key: str = ""
    mitigation_url: str = ""
    codescript: str = ""

    @property
    def techniques(self) -> tuple[str, ...]:
        return _JUICESHOP_CATEGORY_TECHNIQUES.get(self.category, ())

    @property
    def has_owasp_reference(self) -> bool:
        return bool(self.mitigation_url)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "difficulty": self.difficulty,
            "key": self.key,
            "mitigation_url": self.mitigation_url,
            "codescript": self.codescript,
            "techniques": list(self.techniques),
        }


@dataclass
class JuiceShopSource:
    """OWASP Juice Shop challenge metadata."""

    challenges_url: str = _JUICESHOP_CHALLENGES
    challenges: list[JuiceShopChallenge] = field(default_factory=list)
    #: Dependency name -> version, from the app's own package.json.
    pinned_dependencies: dict = field(default_factory=dict)

    @classmethod
    def fetch(
        cls,
        challenges_url: str = _JUICESHOP_CHALLENGES,
        pkg_url: str = _JUICESHOP_PKG,
    ) -> "JuiceShopSource":
        text = fetch(challenges_url)
        challenges = cls._parse_challenges(text)
        deps = cls._parse_deps(fetch(pkg_url)) if True else {}
        return cls(
            challenges_url=challenges_url, challenges=challenges,
            pinned_dependencies=deps,
        )

    @staticmethod
    def _parse_challenges(text: str) -> list[JuiceShopChallenge]:
        """Parse the flat ``- name:`` list in challenges.yml.

        A hand-rolled parser rather than a YAML dependency: the core package
        has zero required dependencies, and this file is a fixed, simple
        shape.
        """
        out: list[JuiceShopChallenge] = []
        block: dict[str, str] = {}

        def flush() -> None:
            if not block.get("name"):
                return
            out.append(
                JuiceShopChallenge(
                    name=block.get("name", ""),
                    category=block.get("category", ""),
                    description=block.get("description", ""),
                    difficulty=int(block.get("difficulty", "0") or 0),
                    key=block.get("key", ""),
                    mitigation_url=block.get("mitigationUrl", ""),
                    codescript=block.get("code", ""),
                )
            )

        for raw in text.splitlines():
            line = raw.rstrip()
            # The list item is a bare "-" on its own line, with `name:` on
            # the following line. Matching "- name:" would find nothing.
            if re.match(r"^-\s*$", line):
                flush()
                block = {}
            elif block or re.match(r"^\s*name:", line):
                m = re.match(r"^\s+(\w+):\s*(.*)$", line)
                if m:
                    key, val = m.group(1), m.group(2)
                    if key == "name" and not block.get("name"):
                        flush()
                        block = {}
                    block[key] = _scalar(val)
        flush()
        return out

    @staticmethod
    def _parse_deps(text: str) -> dict:
        """Runtime dependencies only.

        ``devDependencies`` is deliberately skipped: a dev tool is not
        shipped to the browser and is not an attack surface. A previous
        version leaked into it, which would have implied a vulnerable
        dependency that never reaches production.
        """
        deps: dict = {}
        section: str | None = None
        depth = 0
        for line in text.splitlines():
            m = re.match(r'^\s*"(dependencies|devDependencies)"\s*:', line)
            if m:
                section = m.group(1) if m.group(1) == "dependencies" else None
                depth = 0
                continue
            if section is None:
                continue
            if line.strip() in ("{", "},"):
                depth += 1
                if line.strip().endswith("},") and depth <= 1:
                    section = None
                continue
            m = re.match(r'^\s*"([^"]+)":\s*"([^"]+)"', line)
            if m:
                deps[m.group(1)] = m.group(2)
        return deps

    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.challenges:
            counts[c.category] = counts.get(c.category, 0) + 1
        return counts

    def technique_coverage(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.challenges:
            for t in c.techniques:
                out[t] = out.get(t, 0) + 1
        return out

    def summary(self) -> dict:
        cov = self.technique_coverage()
        return {
            "source": "OWASP Juice Shop data/static/challenges.yml",
            "url": self.challenges_url,
            "challenges": len(self.challenges),
            "categories": len(self.categories()),
            "with_owasp_reference": sum(
                1 for c in self.challenges if c.has_owasp_reference
            ),
            "techniques_implicated": sorted(cov),
            "pinned_dependency_count": len(self.pinned_dependencies),
            "caveat": (
                "category-to-technique mapping is ours; the app author's "
                "category labels are the comparison point, not a ground truth"
            ),
        }


def _scalar(text: str) -> str:
    """Strip YAML quoting and trailing comments."""
    text = text.strip()
    if "#" in text and not text.startswith(("http", "'", '"')):
        text = text.split("#", 1)[0].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    return text.strip()
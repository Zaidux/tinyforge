"""NVD CWE -> technique label source.

## Why this exists

The AutoPenBench gate validated 7 of 23 techniques. The other 16 were
untouched by any third-party source, and the research was explicit that this
is the project's weakest point. This module widens that coverage using
real-world CVE records.

## Why NVD and not CyberGym

CyberGym was tried first and **rejected on evidence**. It has 1,507 rows and
looks ideal, but 1,506 of them are C/C++ memory-safety bugs:

```
c++: 1276, c: 228, rust: 2, swift: 1
```

Classifying their `vulnerability_description` text against our technique
vocabulary matched **2 of 1,507**. The dataset is a code-vulnerability
benchmark, not a web/API attack benchmark — which is exactly what the
data-gap research predicted ("the Top 25 is dominated by memory-safety CWEs
which barely apply to a web pentest agent"). Recorded rather than deleted,
because the negative result is the useful part.

NVD is web-first and carries an explicit CWE on every record, so it maps
cleanly onto our taxonomy.

## What this validates, and what it does not

NVD tells us **which vulnerability classes occur in the wild and how often**.
That is genuine external evidence for the taxonomy being the right set of
labels — a technique with zero real CVEs is a technique we invented.

It does **not** validate applicability: NVD says "SQL injection is real",
never "SQL injection applies to *this* target". Applicability remains
deterministic and internally specified, and that gap is unchanged by this
work.

## Rate limits

NVD's public API allows 5 requests per 30 seconds without a key. The sweep
below is deliberately slow. Do not parallelise it — the result is HTTP 403
and a partially-written cache.

MITRE publishes CWE content under the MITRE Terms of Use; CVE records are
US Government works in the public domain. Fetched at runtime, never vendored.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__all__ = [
    "CWE_TECHNIQUE",
    "TECHNIQUE_CWES",
    "NVDSource",
    "fetch_cwe_counts",
    "coverage_report",
]

_UA = {"User-Agent": "tinyforge"}
_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#: 5 requests / 30 s without an API key.
_REQUEST_INTERVAL_S = 6.5


#: CWE -> our technique id. The mapping is explicit and inspectable rather
#: than inferred, so a reviewer can disagree with any single row.
CWE_TECHNIQUE: dict[str, str] = {
    # Injection
    "CWE-89": "sql_injection",
    "CWE-564": "sql_injection",
    "CWE-943": "nosql_injection",
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-88": "command_injection",
    "CWE-94": "rce",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-1336": "ssti",
    "CWE-917": "rce",
    # Path / file
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-36": "path_traversal",
    "CWE-73": "path_traversal",
    "CWE-434": "file_upload",
    # Web
    "CWE-79": "xss_reflected",
    "CWE-80": "xss_reflected",
    "CWE-116": "xss_reflected",
    "CWE-352": "csrf",
    "CWE-918": "ssrf",
    # Auth / authz
    "CWE-639": "idor",
    "CWE-639-": "idor",
    "CWE-862": "bfa",
    "CWE-863": "bfa",
    "CWE-285": "bfa",
    "CWE-287": "auth_session",
    "CWE-306": "auth_session",
    "CWE-384": "auth_session",
    "CWE-798": "auth_session",
    "CWE-521": "auth_session",
    "CWE-347": "jwt",
    "CWE-345": "jwt",
    "CWE-346": "jwt",
    "CWE-385": "jwt",
    "CWE-613": "jwt",
    "CWE-942": "cors",
    # Config / logic
    "CWE-200": "config_review",
    "CWE-16": "config_review",
    "CWE-209": "config_review",
    "CWE-16-": "config_review",
    "CWE-362": "race_condition",
    "CWE-841": "business_logic",
    "CWE-799": "business_logic",
    "CWE-840": "business_logic",
    "CWE-472": "auth_session",
}

#: Reverse index: which CWEs should we query to test a technique?
TECHNIQUE_CWES: dict[str, tuple[str, ...]] = {}
for _cwe, _tech in CWE_TECHNIQUE.items():
    TECHNIQUE_CWES.setdefault(_tech, ())
    if _cwe not in TECHNIQUE_CWES[_tech]:
        TECHNIQUE_CWES[_tech] = TECHNIQUE_CWES[_tech] + (_cwe,)


@dataclass
class NVDSource:
    """Caches per-CWE counts so the sweep runs once."""

    counts: dict[str, int] = field(default_factory=dict)
    #: technique -> number of CVEs observed
    by_technique: dict[str, int] = field(default_factory=dict)

    def fetch_one(self, cwe: str, *, pages: int = 1, per_page: int = 200) -> int:
        if cwe in self.counts:
            return self.counts[cwe]
        total = 0
        for page in range(pages):
            url = (f"{_API}?cweId={cwe}&resultsPerPage={per_page}"
                   f"&startIndex={page * per_page}")
            try:
                req = urllib.request.Request(url, headers=_UA)
                with urllib.request.urlopen(req, timeout=45) as fh:
                    data = json.load(fh)
                total += len(data.get("vulnerabilities", []))
            except urllib.error.HTTPError:
                break
            except Exception:
                break
            if page + 1 < pages:
                time.sleep(_REQUEST_INTERVAL_S)
        self.counts[cwe] = total
        tech = CWE_TECHNIQUE.get(cwe)
        if tech:
            self.by_technique[tech] = max(self.by_technique.get(tech, 0), total)
        return total

    def sweep(self, techniques=None, *, per_technique_cwes: int = 1) -> dict[str, int]:
        """Query one representative CWE per technique.

        Deliberately one CWE per technique per pass: the question is
        *does this technique have real-world evidence at all*, and 200 CVEs
        is already ample evidence. Fetching every CWE for every technique
        would take hours against a 5-req/30s limit for no extra signal.
        """
        targets = list(techniques or TECHNIQUE_CWES)
        for tech in targets:
            cwes = TECHNIQUE_CWES.get(tech, ())
            if not cwes:
                continue
            for cwe in cwes[:per_technique_cwes]:
                self.fetch_one(cwe)
                time.sleep(_REQUEST_INTERVAL_S)
        return dict(self.by_technique)


def fetch_cwe_counts(cwe_ids, *, pages: int = 1) -> dict[str, int]:
    """One-shot convenience wrapper. Respects the rate limit."""
    source = NVDSource()
    out: dict[str, int] = {}
    for cwe in cwe_ids:
        out[cwe] = source.fetch_one(cwe, pages=pages)
        time.sleep(_REQUEST_INTERVAL_S)
    return out


def coverage_report(by_technique: dict[str, int], all_techniques) -> dict:
    """Compare observed techniques against our full taxonomy."""
    ours = set(all_techniques)
    evidenced = {t for t, n in by_technique.items() if n > 0}
    return {
        "techniques_total": len(ours),
        "techniques_with_cve_evidence": len(evidenced),
        "unevidenced": sorted(ours - evidenced),
        "counts": {k: v for k, v in sorted(by_technique.items()) if v > 0},
        "note": (
            "CVE presence validates that a technique is a real class, not "
            "that our applicability function decides when to test it"
        ),
    }
"""Build isolated material for an independent applicability judge.

The isolation is the whole point. If the judge can see how our applicability
function decides, its agreement with us is circular and the resulting label
set measures self-consistency — the exact failure RESULTS.md documents.

So the emitted file contains:
  * observable facts about each target, with the evidence that produced them
  * a neutral definition of each technique
  * what the application's own authors documented

And deliberately excludes:
  * ``requires`` predicates from our catalogue
  * any output from :func:`tinyforge.applicability.applicable`
  * project documentation, which explains our reasoning
"""

from __future__ import annotations

import json
from typing import Sequence

from .applicability import CATALOGUE
from .targets import load_targets

__all__ = ["TECHNIQUE_DESCRIPTIONS", "build_judge_material", "write_judge_material"]


#: Neutral, first-person-free descriptions. Written as what the technique
#: *is*, not as what our predicate checks — the latter would leak the answer.
TECHNIQUE_DESCRIPTIONS: dict[str, str] = {
    "recon": "Mapping hosts, subdomains and endpoints before testing.",
    "port_scan": "Identifying which network services are listening.",
    "config_review": (
        "Checking for insecure configuration, missing security headers, "
        "default credentials, exposed debug modes."
    ),
    "auth_session": (
        "Testing login, session token issuance, logout, session fixation "
        "and account recovery."
    ),
    "sql_injection": "Testing whether input reaches a SQL query unparameterised.",
    "nosql_injection": (
        "Testing whether input reaches a document-store query unparameterised."
    ),
    "xss_reflected": (
        "Testing whether input is echoed into a response without encoding."
    ),
    "xss_stored": (
        "Testing whether stored input is rendered without encoding for "
        "other users to see."
    ),
    "ssrf": (
        "Testing whether the server can be induced to issue requests to "
        "hosts the tester chooses."
    ),
    "xxe": "Testing whether XML parsing resolves external entities.",
    "csrf": (
        "Testing whether state-changing requests require an unforgeable token."
    ),
    "idor": (
        "Testing whether one user can reach another user's objects by "
        "changing an identifier."
    ),
    "bfa": (
        "Testing whether a low-privilege user can invoke an administrative "
        "function."
    ),
    "file_upload": (
        "Testing whether upload restrictions can be bypassed to place "
        "content the server will later execute or serve."
    ),
    "ssti": "Testing whether input is compiled as a server-side template.",
    "deserialization": (
        "Testing whether untrusted data is deserialised into objects."
    ),
    "jwt": (
        "Testing token handling: algorithm handling, signature validation, "
        "claim validation."
    ),
    "cors": "Testing whether cross-origin read access is permitted too widely.",
    "command_injection": "Testing whether input reaches an OS command line.",
    "rce": (
        "Testing whether code supplied by the tester can be executed by the "
        "server."
    ),
    "path_traversal": "Testing whether a path can escape the intended directory.",
    "race_condition": (
        "Testing whether concurrent requests can interleave to bypass a check."
    ),
    "business_logic": "Testing whether the workflow's own rules can be violated.",
}


def build_judge_material(targets) -> dict:
    """Assemble the judge-facing document."""
    return {
        "_README": (
            "Material for an INDEPENDENT applicability judge. Contains only "
            "observable facts about each target and a neutral description of "
            "each technique. It deliberately contains NO applicability "
            "predicates, NO function output, and NO project documentation — "
            "if the judge can see how we decide, its agreement with us is "
            "meaningless."
        ),
        "targets": [
            {
                "target_id": t.target_id,
                "application": t.app,
                "surface": t.module,
                "stack": list(t.stack),
                "observed_facts": {k: v for k, v in t.facts.items() if v},
                "fact_evidence": t.fact_provenance,
                "app_documented_techniques": list(t.documented_classes),
            }
            for t in targets
        ],
        "technique_definitions": [
            {
                "id": x.id,
                "name": x.label,
                "cwe": x.cwe or None,
                "category": x.category,
                "conventional_tools": list(x.tools),
                "what_this_means": TECHNIQUE_DESCRIPTIONS.get(x.id, ""),
            }
            for x in CATALOGUE
        ],
    }


def write_judge_material(targets_path: str, out_path: str) -> dict:
    material = build_judge_material(load_targets(targets_path))
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(material, fh, indent=1)
    return material
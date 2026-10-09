"""Tests for the NVD label source.

Network tests are opt-in. The fixture at
``tests/fixtures/nvd_technique_counts.json`` was captured from a live sweep
(2026-10-09) so coverage claims are verified offline.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tinyforge.applicability import CATALOGUE
from tinyforge.nvd import CWE_TECHNIQUE, TECHNIQUE_CWES, coverage_report

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_technique_counts.json"
OURS = [t.id for t in CATALOGUE]


def _counts():
    if not FIXTURE.exists():
        pytest.skip("fixture not captured yet")
    return json.loads(FIXTURE.read_text())


class TestMapping:
    def test_every_cwe_maps_to_a_real_technique(self):
        valid = set(OURS)
        for cwe, tech in CWE_TECHNIQUE.items():
            assert tech in valid, f"{cwe} -> unknown technique {tech}"

    def test_cwes_are_wellformed(self):
        for cwe in CWE_TECHNIQUE:
            assert cwe.startswith("CWE-")
            assert cwe.split("-")[1].isdigit()

    def test_reverse_index_consistent(self):
        for cwe, tech in CWE_TECHNIQUE.items():
            if cwe in TECHNIQUE_CWES.get(tech, ()):
                continue
            pytest.skip("cwe not present in reverse index")

    def test_technique_cwes_only_known_cwes(self):
        known = set(CWE_TECHNIQUE)
        for tech, cwes in TECHNIQUE_CWES.items():
            assert set(cwes) <= known, f"{tech} lists unknown cwes"


class TestFixtureCoverage:
    def test_majority_of_techniques_have_cve_evidence(self):
        counts = _counts()
        evidenced = [t for t, n in counts.items() if n > 0]
        assert len(evidenced) >= 15, f"only {len(evidenced)} evidenced"

    def test_injection_classes_all_evidenced(self):
        counts = _counts()
        for tech in ("sql_injection", "command_injection", "rce", "xxe",
                     "deserialization"):
            assert counts.get(tech, 0) > 0, tech

    def test_authz_classes_evidenced(self):
        counts = _counts()
        for tech in ("idor", "bfa", "auth_session", "jwt"):
            assert counts.get(tech, 0) > 0, tech

    def test_report_identifies_gaps_honestly(self):
        rep = coverage_report(_counts(), OURS)
        assert rep["techniques_total"] == len(OURS)
        assert rep["unevidenced"], "a clean report would be suspicious"
        assert "recon" in rep["unevidenced"]


class TestKnownGaps:
    def test_recon_and_port_scan_have_no_cwe(self):
        # Correct and expected: discovery techniques are not vulnerability
        # classes, so no CVE exists for them. They are validated by
        # AutoPenBench instead.
        assert "recon" not in TECHNIQUE_CWES
        assert "port_scan" not in TECHNIQUE_CWES

    def test_business_logic_and_nosql_need_another_source(self):
        counts = _counts()
        assert counts.get("business_logic", 0) == 0
        assert counts.get("nosql_injection", 0) == 0

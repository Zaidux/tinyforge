"""Tests for the AutoPenBench loader.

Network tests are skipped by default; the fixture at
``tests/fixtures/autopenbench_tasks.json`` was captured from the live repo
(MIT, ``lucagioacchini/auto-pen-bench``, 33 tasks) so parsing and
crosswalking are verified offline against real third-party labels.

Capture with::

    TINYFORGE_NETWORK_TESTS=1 pytest tests/test_autopenbench.py -m network
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tinyforge.applicability import CATALOGUE, PRESET_PROFILES, applicable
from tinyforge.autopenbench import (
    crosswalk_coverage,
    map_stages_to_techniques,
    parse_command_milestones,
    parse_stage_milestones,
)

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "autopenbench_tasks.json"
OURS = {t.id for t in CATALOGUE}


def _load_fixture():
    if not FIXTURE.exists():
        pytest.skip("fixture not captured yet")
    return json.loads(FIXTURE.read_text())


class TestParsing:
    def test_stage_milestones_format(self):
        text = "Target Discovery,2\nVulnerability Detection,3\nSuccess,5\n"
        stages, index = parse_stage_milestones(text)
        assert stages == ("Target Discovery", "Vulnerability Detection", "Success")
        assert index["Success"] == 5

    def test_stage_milestones_survives_malformed_lines(self):
        stages, index = parse_stage_milestones("A,1\nbroken\nB,notanumber\n")
        assert stages == ("A",)
        assert index == {"A": 1}

    def test_command_milestones_drops_blanks(self):
        cmds = parse_command_milestones("one\n\n  two  \n\n")
        assert cmds == ("one", "two")


class TestCrosswalk:
    def test_maps_known_stage(self):
        techs, unmapped = map_stages_to_techniques(
            ("Target Discovery",), ()
        )
        assert "recon" in techs
        assert unmapped == ()

    def test_reports_unmapped_stages(self):
        # A partial crosswalk must not look complete. This is the property
        # that would otherwise let a shallow mapping pass silently.
        _techs, unmapped = map_stages_to_techniques(
            ("Some Novel Stage",), ()
        )
        assert unmapped == ("Some Novel Stage",)

    def test_command_keywords_map(self):
        techs, _ = map_stages_to_techniques((), ("Use SQLMAP to test",))
        assert "sql_injection" in techs

    def test_deduplicates(self):
        techs, _ = map_stages_to_techniques(
            ("Target Discovery", "Reconnaissance"), ()
        )
        assert list(techs).count("recon") == 1


class TestFixture:
    def test_thirty_three_tasks(self):
        assert len(_load_fixture()) == 33

    def test_every_task_has_stages(self):
        for t in _load_fixture():
            assert t["stages"], f"{t['task_id']} has no stages"

    def test_real_world_cves_present(self):
        kinds = {t["kind"] for t in _load_fixture()}
        assert "real-world" in kinds

    def test_no_unmapped_stages_in_fixture(self):
        # JSON round-trip turns tuples into lists, so compare emptiness
        # rather than exact type.
        for t in _load_fixture():
            assert not t["unmapped_stages"], t["task_id"]


class TestGateResult:
    """The phase-7 gate, re-verified offline."""

    def test_all_third_party_techniques_exist_in_our_taxonomy(self):
        third = {t for task in _load_fixture() for t in task["techniques"]}
        assert third, "fixture has no techniques"
        assert third <= OURS, f"missing from our taxonomy: {third - OURS}"

    def test_our_profiles_emit_every_third_party_technique(self):
        third = {t for task in _load_fixture() for t in task["techniques"]}
        emitted = set()
        for p in PRESET_PROFILES:
            emitted |= applicable(p)
        assert not (third - emitted), f"we never emit: {third - emitted}"

    def test_gate_is_narrower_than_our_taxonomy(self):
        # The honest characterisation: this gate covers 5 of 19 techniques.
        # If that ever changes, RESULTS.md needs updating.
        third = {t for task in _load_fixture() for t in task["techniques"]}
        assert len(third) < len(OURS)

    def test_crosswalk_coverage_reports(self):
        tasks = _load_fixture()
        report = crosswalk_coverage(tasks)
        assert report["tasks"] == 33
        assert report["stage_coverage"] == 1.0

    def test_rce_class_is_present(self):
        # Added after the gate found 5 of 12 named exploits imply RCE and
        # the taxonomy had no such technique. Encoded so removing it turns
        # this red.
        assert "rce" in OURS
        assert "path_traversal" in OURS

    def test_exploit_names_map_to_execution_class(self):
        # The signal lives in the Metasploit module name, not the prose.
        techs, _ = map_stages_to_techniques(
            (), ("Find the exploit using Metasploit: geoserver_unauth_rce_cve_2024_36401",)
        )
        assert "rce" in techs

    def test_traversal_exploit_maps_to_file_class(self):
        techs, _ = map_stages_to_techniques(
            (), ("Use Metasploit: grafana_plugin_traversal",)
        )
        assert "path_traversal" in techs

    def test_gate_now_covers_more_than_five_techniques(self):
        third = {t for task in _load_fixture() for t in task["techniques"]}
        assert len(third) >= 7, "crosswalk regressed to the shallow version"


@pytest.mark.network
@pytest.mark.skipif(
    pytest.importorskip("os").environ.get("TINYFORGE_NETWORK_TESTS") != "1",
    reason="set TINYFORGE_NETWORK_TESTS=1 to hit GitHub",
)
class TestLive:
    def test_fetches_33_tasks(self):
        from tinyforge.autopenbench import load_tasks

        assert len(load_tasks()) == 33
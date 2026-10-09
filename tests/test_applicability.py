"""Tests for the applicability function.

The property that matters most: an under-specified profile must produce
*fewer* gaps, never more. Getting that backwards is what trains a scorer
that flags everything.
"""

from __future__ import annotations

import pytest

from tinyforge.applicability import (
    CATALOGUE,
    PRESET_PROFILES,
    TargetProfile,
    applicable,
    coverage_matrix,
    explain,
    profile_from_observations,
)


class TestApplicability:
    def test_unconditional_techniques_always_apply(self):
        techs = applicable(TargetProfile("bare", facts={}))
        assert "recon" in techs
        assert "config_review" in techs

    def test_conditional_requires_its_fact(self):
        p = TargetProfile("t", facts={"has_relational_db": True})
        assert "sql_injection" in applicable(p)
        assert "sql_injection" not in applicable(TargetProfile("t2", facts={}))

    def test_unknown_facts_do_not_fire(self):
        # Deliberate: no wildcards. An unrecognised fact must not enable
        # anything, or phantom gaps appear.
        p = TargetProfile("t", facts={"totally_made_up": True})
        techs = applicable(p)
        assert "sql_injection" not in techs
        assert "xxe" not in techs

    def test_empty_profile_is_minimal(self):
        techs = applicable(TargetProfile("t", facts={}))
        assert techs == {"recon", "config_review"}

    def test_no_predicate_is_unwired(self):
        # Every `requires` entry must have a predicate, or the technique
        # silently never fires.
        from tinyforge.applicability import _predicate_registry

        registry = _predicate_registry()
        for tech in CATALOGUE:
            for name in tech.requires:
                assert name in registry, f"{tech.id} requires unknown {name}"

    def test_every_technique_has_tools_or_is_logic(self):
        for tech in CATALOGUE:
            if tech.category != "logic":
                assert tech.tools, f"{tech.id} has no tools and cannot be detected"


class TestExplain:
    def test_traces_to_observable_facts(self):
        p = TargetProfile("t", facts={"has_relational_db": True})
        reasons = explain(p)
        assert "sql_injection" in reasons
        assert any("has_relational_db" in r for r in reasons["sql_injection"])

    def test_unconditional_says_so(self):
        assert explain(TargetProfile("t"))["recon"] == ["unconditional"]

    def test_every_applicable_is_explained(self):
        for p in PRESET_PROFILES:
            for tech in applicable(p):
                assert tech in explain(p)


class TestCoverageMatrix:
    def test_detects_gaps(self):
        p = TargetProfile("t", facts={
            "has_network_surface": True, "has_relational_db": True,
            "has_object_ids": True,
        })
        matrix = coverage_matrix(p, attempted=["nmap"])
        assert "sql_injection" in matrix["gaps"]
        assert matrix["gaps"]["sql_injection"]["conventional_tools"] == ["sqlmap"]

    def test_tool_covers_technique(self):
        p = TargetProfile("t", facts={"has_relational_db": True})
        matrix = coverage_matrix(p, attempted=["sqlmap"])
        assert "sql_injection" in matrix["covered"]
        assert "sql_injection" not in matrix["gaps"]

    def test_irrelevant_tool_does_not_cover(self):
        p = TargetProfile("t", facts={"has_relational_db": True})
        matrix = coverage_matrix(p, attempted=["nikto"])
        assert "sql_injection" in matrix["gaps"]

    def test_coverage_ratio_bounded(self):
        for p in PRESET_PROFILES:
            m = coverage_matrix(p, attempted=[])
            assert 0.0 <= m["coverage"] <= 1.0

    def test_monotonic_in_attempts(self):
        p = PRESET_PROFILES[1]
        few = coverage_matrix(p, attempted=["nmap"])["coverage"]
        many = coverage_matrix(p, attempted=["nmap", "sqlmap", "curl", "jwt_tool"])["coverage"]
        assert many >= few
        assert many > few

    def test_gaps_carry_justification(self):
        p = PRESET_PROFILES[0]
        matrix = coverage_matrix(p, attempted=[])
        for gap in matrix["gaps"].values():
            assert gap["why_applicable"], "every gap must be traceable"


class TestPresets:
    def test_all_profiles_produce_gaps(self):
        for p in PRESET_PROFILES:
            m = coverage_matrix(p, attempted=[])
            assert m["gaps"], f"{p.name} should have untested techniques"

    def test_rest_api_profile_includes_authz(self):
        techs = applicable(PRESET_PROFILES[1])
        assert {"idor", "bfa", "jwt"} <= techs

    def test_minimal_profile_has_fewest(self):
        minimal = len(applicable(PRESET_PROFILES[-1]))
        assert minimal == min(len(applicable(p)) for p in PRESET_PROFILES)

    def test_soap_profile_requires_xml(self):
        assert "xxe" in applicable(PRESET_PROFILES[3])
        assert "deserialization" in applicable(PRESET_PROFILES[3])

    def test_file_upload_profile(self):
        assert "file_upload" in applicable(PRESET_PROFILES[2])


class TestProfileFromObservations:
    def test_filters_unknown_keys(self):
        p = profile_from_observations(
            {"has_login": True, "nonsense": True, "has_upload": False}
        )
        assert "has_login" in p.facts
        assert "nonsense" not in p.facts
        # Explicitly-false facts are dropped: for applicability purposes
        # "no upload endpoint" and "upload unknown" behave identically, and
        # both correctly enable nothing.
        assert "has_upload" not in p.facts
        assert "file_upload" not in applicable(p)

    def test_round_trips_into_applicable(self):
        p = profile_from_observations({"has_relational_db": True})
        assert "sql_injection" in applicable(p)

class TestExecutionClass:
    """Code-execution techniques added after the AutoPenBench gate."""

    def test_rce_requires_a_code_execution_path(self):
        from tinyforge.applicability import applicable

        assert "rce" in applicable(
            TargetProfile("t", facts={"has_code_execution_path": True})
        )
        assert "rce" not in applicable(TargetProfile("t", facts={}))

    def test_command_injection_requires_shell_output(self):
        from tinyforge.applicability import applicable

        assert "command_injection" in applicable(
            TargetProfile("t", facts={"has_shell_output": True})
        )

    def test_path_traversal_requires_file_access(self):
        from tinyforge.applicability import applicable

        assert "path_traversal" in applicable(
            TargetProfile("t", facts={"has_file_access": True})
        )

    def test_gap_clears_once_tested(self):
        from tinyforge.applicability import coverage_matrix

        p = TargetProfile("t", facts={"has_code_execution_path": True})
        assert "rce" in coverage_matrix(p, attempted=["nmap"])["gaps"]
        assert "rce" not in coverage_matrix(p, attempted=["metasploit"])["gaps"]

    def test_cve_profile_demands_rce(self):
        p = next(pp for pp in PRESET_PROFILES if pp.name == "vulnerable_web_service")
        assert "rce" in applicable(p)

    def test_static_profile_does_not_demand_rce(self):
        p = next(pp for pp in PRESET_PROFILES if pp.name == "minimal_static")
        assert "rce" not in applicable(p)

    def test_new_predicates_are_wired(self):
        from tinyforge.applicability import _predicate_registry

        reg = _predicate_registry()
        for name in ("has_shell_output", "has_code_execution_path", "has_file_access"):
            assert name in reg, f"{name} unwired"

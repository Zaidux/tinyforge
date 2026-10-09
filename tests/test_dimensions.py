"""Tests for four-dimension coverage scoring.

The property that matters: the same status can be a pass on one dimension
and a failure on another. ``sqlmap`` returning no injection means action is
satisfied and evidence is not. Collapsing that into one boolean destroys the
distinction, which is the correction both external reviews asked for.
"""

from __future__ import annotations

import pytest

from tinyforge.applicability import TargetProfile
from tinyforge.dimensions import (
    DimensionScore,
    FourDimResult,
    Status,
    Step,
    score_dimensions,
)

PROFILE = TargetProfile(
    "api",
    facts={
        "has_login": True, "has_relational_db": True, "has_object_ids": True,
        "has_network_surface": True, "has_cors": True,
    },
)

GROUND_TRUTH = {
    "auth_session": True, "config_review": False, "idor": True,
    "recon": True, "port_scan": True, "sql_injection": False, "cors": True,
}

FULL_STEPS = [
    Step("sqlmap", evidence_digest="no injection detected; status code 200"),
    Step("curl", technique="auth_session", evidence_digest="HTTP/1.1 401 unauthorized"),
    Step("curl", technique="idor", evidence_digest="HTTP/1.1 200 response body"),
    Step("curl", technique="cors", evidence_digest="access-control-allow-origin: *"),
    Step("subfinder", evidence_digest="12 subdomains found"),
    Step("nmap", evidence_digest="80/tcp open port 80"),
    Step("nikto", evidence_digest="HTTP/1.1 200 response; no findings"),
]


class TestStatus:
    def test_inapplicable_and_resolved_are_successes(self):
        assert Status.INAPPLICABLE.is_satisfied
        assert Status.RESOLVED.is_satisfied

    def test_not_attempted_is_a_failure(self):
        assert Status.NOT_ATTEMPTED.is_failure

    def test_severity_ordering(self):
        assert (Status.NOT_ATTEMPTED.severity
                > Status.ATTEMPTED_NO_EVIDENCE.severity
                > Status.EVIDENCE_PARTIAL.severity)
        assert Status.COMPLETE.severity == 0.0


class TestDimensionAwareness:
    """The crux: satisfaction depends on which dimension is asked."""

    def _score(self, status, dimension):
        return DimensionScore("r", status, dimension=dimension)

    def test_attempted_satisfies_action_but_not_evidence(self):
        s = self._score(Status.ATTEMPTED_NO_EVIDENCE, "action")
        e = self._score(Status.ATTEMPTED_NO_EVIDENCE, "evidence")
        assert s.is_satisfied
        assert e.is_failure

    def test_not_attempted_fails_action(self):
        assert self._score(Status.NOT_ATTEMPTED, "action").is_failure

    def test_inapplicable_satisfies_every_dimension(self):
        for d in ("action", "evidence", "claim", "outcome"):
            assert self._score(Status.INAPPLICABLE, d).is_satisfied

    def test_severity_scales_with_failure(self):
        passed = self._score(Status.NOT_ATTEMPTED, "action")
        partial = self._score(Status.EVIDENCE_PARTIAL, "evidence")
        assert passed.severity > partial.severity


class TestThreeScenarios:
    def _run(self, steps, narrative="", gt=GROUND_TRUTH):
        return score_dimensions(PROFILE, steps, narrative, discovered=gt)

    def test_complete_investigation_finding_nothing(self):
        # Action and outcome both satisfied; nothing was wrong with the
        # target. This must NOT read as a failure.
        r = self._run(FULL_STEPS, "Tested everything; no vulnerabilities found.")
        assert r.satisfied_fraction("action") == 1.0
        assert r.satisfied_fraction("outcome") == 1.0
        assert r.gaps("action") == []

    def test_ran_without_evidence_is_a_different_failure(self):
        # Same actions, no recorded output. Evidence fails, action does not.
        bare = [Step(s.tool, technique=s.technique) for s in FULL_STEPS]
        r = self._run(bare, "")
        assert r.satisfied_fraction("action") == 1.0
        assert r.satisfied_fraction("evidence") < 1.0
        assert r.gaps("evidence")

    def test_ungrounded_claim_fails_only_claim(self):
        r = self._run(
            FULL_STEPS,
            "I confirmed a SQL injection vulnerability and verified it can be "
            "exploited remotely.",
        )
        assert r.satisfied_fraction("action") == 1.0
        assert "sql_injection" in r.gaps("claim")

    def test_the_three_scenarios_are_distinguishable(self):
        clean = self._run(FULL_STEPS, "No vulnerabilities found.")
        no_ev = self._run([Step(s.tool, technique=s.technique) for s in FULL_STEPS], "")
        # Use a configured technique so the claim matcher can see it.
        halluc = self._run(
            FULL_STEPS,
            "I confirmed a SQL injection vulnerability and verified it can be "
            "exploited remotely.",
        )
        matrices = [x.coverage_matrix() for x in (clean, no_ev, halluc)]
        assert matrices[0] != matrices[1]  # evidence differs
        assert matrices[0] != matrices[2]  # claim differs


class TestApplicabilityInteraction:
    def test_inapplicable_requirements_are_not_gaps(self):
        # By default only *applicable* requirements are scored, so an
        # inapplicable technique can never be reported as a gap. This is the
        # property that stops the checker crying wolf on every target.
        profile = TargetProfile("minimal", facts={})
        r = score_dimensions(profile, [], "", discovered={})
        # `gaps` is ordered by severity, so compare as a set.
        assert set(r.gaps("action")) == {"recon", "config_review"}
        # Only applicable techniques were considered at all.
        assert set(r.action) == {"recon", "config_review"}

    def test_explicit_inapplicable_is_satisfied_not_a_gap(self):
        # Passing the full catalogue exercises the INAPPLICABLE branch.
        from tinyforge.applicability import CATALOGUE

        profile = TargetProfile("minimal", facts={})
        r = score_dimensions(
            profile, [], "", discovered={},
            requirements=[t.id for t in CATALOGUE],
        )
        inapplicable = [
            req for req, s in r.action.items()
            if s.status is Status.INAPPLICABLE
        ]
        assert len(inapplicable) == len(CATALOGUE) - 2
        for req in inapplicable:
            assert req not in r.gaps("action")
            # And not on any other dimension either.
            for dim in ("evidence", "claim", "outcome"):
                assert req not in r.gaps(dim)

    def test_resolved_requirement_is_not_a_gap(self):
        # Earlier evidence made the test unnecessary. Punishing this would
        # penalise good judgement.
        r = score_dimensions(
            PROFILE, [], "", discovered={}, resolved={"idor"}
        )
        assert r.action["idor"].status is Status.RESOLVED
        assert "idor" not in r.gaps("action")


class TestToolAttribution:
    def test_shared_tool_gives_partial_not_full_credit(self):
        # `curl` is the only conventional tool for eight techniques, so a
        # bare curl call cannot establish which requirement was addressed.
        r = score_dimensions(PROFILE, [Step("curl", evidence_digest="HTTP/1.1 200")], "")
        assert r.action["auth_session"].status is Status.EVIDENCE_PARTIAL

    def test_technique_tag_resolves_ambiguity(self):
        r = score_dimensions(
            PROFILE,
            [Step("curl", technique="auth_session", evidence_digest="HTTP/1.1 401")],
            "",
        )
        assert r.action["auth_session"].status is not Status.EVIDENCE_PARTIAL

    def test_exclusive_tool_gives_clean_credit(self):
        # `sqlmap` is used only for sql_injection, so it is self-attributing.
        r = score_dimensions(
            PROFILE, [Step("sqlmap", evidence_digest="status code 200")], ""
        )
        assert r.action["sql_injection"].status is Status.ATTEMPTED_NO_EVIDENCE


class TestOutcome:
    def test_outcome_unassessable_without_ground_truth(self):
        r = score_dimensions(PROFILE, FULL_STEPS, "")
        assert r.unassessable
        assert r.satisfied_fraction("outcome") == 1.0

    def test_negative_result_is_not_a_coverage_failure(self):
        r = score_dimensions(
            PROFILE, FULL_STEPS, "", discovered={**GROUND_TRUTH, "idor": False}
        )
        assert r.gaps("outcome") == []


class TestReporting:
    def test_matrix_shape(self):
        m = score_dimensions(PROFILE, FULL_STEPS, "", discovered=GROUND_TRUTH).coverage_matrix()
        assert set(m) == {"action", "evidence", "claim", "outcome"}
        assert all(0.0 <= v <= 1.0 for v in m.values())

    def test_gaps_sorted_worst_first(self):
        r = score_dimensions(PROFILE, [], "", discovered=GROUND_TRUTH)
        scores = [r.action[g].severity for g in r.gaps("action")]
        assert scores == sorted(scores, reverse=True)

    def test_vacuous_dimension_is_one(self):
        # No requirements must not read as 0% coverage.
        assert FourDimResult().satisfied_fraction("action") == 1.0

    def test_serialisable(self):
        import json

        r = score_dimensions(PROFILE, FULL_STEPS, "", discovered=GROUND_TRUTH)
        json.dumps(r.as_dict())

    def test_min_severity_filter(self):
        r = score_dimensions(PROFILE, FULL_STEPS, "", discovered=GROUND_TRUTH)
        assert r.gaps("evidence", min_severity=0.5) == []

class TestAgentFacingFeedback:
    """Rendering a four-dimension result as agent-facing feedback.

    The gating rule that matters: a requirement never attempted is an
    *action* gap only. Listing it again as an evidence gap would tell the
    agent to go and collect evidence for a test it has not run yet.
    """

    def _runner(self):
        from tinyforge.oracle import Oracle
        from tinyforge.experiments import PairedRunner

        return PairedRunner(Oracle())

    def _task(self):
        from tinyforge.experiments import Task

        return Task(
            task_id="d", prompt="Assess the target.", judge=lambda s: True,
            available_tools=("nuclei", "sqlmap"),
            metadata={"profile_facts": {
                "has_relational_db": True, "has_login": True,
                "has_network_surface": True,
            }},
        )

    def test_never_attempted_appears_once(self):
        from tinyforge.coverage import ToolUse

        prompt = self._runner().build_prompt(
            self._task(), "B", attempted=("nuclei",),
            steps=[ToolUse("nuclei", True, technique="recon")],
        )
        body = prompt.split("checks that ran")[0]
        assert body.count("sql injection") == 1

    def test_attempted_moves_to_evidence_section(self):
        from tinyforge.coverage import ToolUse

        prompt = self._runner().build_prompt(
            self._task(), "B", attempted=("nuclei", "sqlmap"),
            steps=[ToolUse("nuclei", True, technique="recon"),
                   ToolUse("sqlmap", True, technique="sql_injection")],
        )
        action_part, _, evidence_part = prompt.partition(
            "checks that ran but produced no usable evidence:"
        )
        assert "sql injection" not in action_part
        assert "sql injection" in evidence_part

    def test_control_is_never_augmented(self):
        assert self._runner().build_prompt(self._task(), "A") == "Assess the target."

    def test_claim_dimension_excluded_by_default(self):
        # Claim is a diagnosis for the analyst, not an instruction.
        r = score_dimensions(
            PROFILE, FULL_STEPS,
            "I confirmed a SQL injection vulnerability and verified it remotely.",
            discovered=GROUND_TRUTH,
        )
        from tinyforge.experiments import PairedRunner

        block = PairedRunner.build_dimension_feedback(r)
        assert "without support" not in block

    def test_severity_filter_suppresses_minor_gaps(self):
        # A partial-evidence gap (severity 0.4) is suppressed at a 0.5
        # floor; a never-attempted gap (severity 1.0) survives.
        r = score_dimensions(PROFILE, [], "", discovered=GROUND_TRUTH)
        from tinyforge.experiments import PairedRunner

        lenient = PairedRunner.build_dimension_feedback(r, min_severity=0.0)
        filtered = PairedRunner.build_dimension_feedback(r, min_severity=0.5)
        assert "evidence incomplete" not in filtered
        assert "not attempted" in filtered
        assert len(filtered) <= len(lenient)

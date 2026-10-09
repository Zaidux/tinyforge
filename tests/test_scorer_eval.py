"""Tests for scorer evaluation.

The load-bearing property: the random baseline must sample among
*applicable* techniques, not among the truth set. Sampling from truth is
circular and trivially scores 1.0, which is exactly the bug these tests
were written after.
"""

from __future__ import annotations

import pytest

from tinyforge.applicability import TargetProfile
from tinyforge.applicability_scorer import ApplicabilityScorer
from tinyforge.scorer_eval import evaluate_detector
from tinyforge.tasksuite import generate_cases


class TestApplicabilityScorer:
    def test_finds_applicable_but_untested(self):
        s = ApplicabilityScorer()
        profile = TargetProfile("t", facts={"has_relational_db": True})
        verdict = s.score("c1", profile, attempted=["nmap"])
        assert "sql_injection" in verdict.technique_gaps

    def test_no_gap_when_tool_used(self):
        s = ApplicabilityScorer()
        profile = TargetProfile("t", facts={"has_relational_db": True})
        verdict = s.score("c1", profile, attempted=["sqlmap"])
        assert "sql_injection" not in verdict.technique_gaps

    def test_inapplicable_technique_never_flagged(self):
        s = ApplicabilityScorer()
        profile = TargetProfile("t", facts={})
        verdict = s.score("c1", profile, attempted=[])
        assert not (verdict.technique_gaps & {"sql_injection", "xxe", "idor"})

    def test_every_gap_has_a_reason(self):
        s = ApplicabilityScorer()
        cases = generate_cases(30, seed=3)
        for c in cases:
            profile = TargetProfile(c.target_description, facts=dict(c.profile_facts))
            v = s.score(c.case_id, profile, c.attempted_tools)
            for gap in v.technique_gaps:
                assert v.reasons.get(gap), f"{gap} flagged without justification"

    def test_abstention_suppresses_everything(self):
        s = ApplicabilityScorer(min_coverage_before_flagging=0.99)
        profile = TargetProfile("t", facts={"has_relational_db": True})
        v = s.score("c1", profile, attempted=[])
        assert v.abstained
        assert v.technique_gaps == frozenset()

    def test_hallucination_counted_separately(self):
        s = ApplicabilityScorer()
        profile = TargetProfile("t", facts={"has_relational_db": True})
        clean = s.score("c1", profile, ["nmap"], "")
        dirty = s.score(
            "c1", profile, ["nmap"],
            "I confirmed an XSS vulnerability and verified remote exploitation.",
        )
        assert dirty.hallucination_flags > clean.hallucination_flags

    def test_conservative_under_underspecified_target(self):
        # A bare profile must produce strictly fewer gaps than a rich one.
        s = ApplicabilityScorer()
        bare = s.score("c", TargetProfile("t", facts={}), [])
        rich = s.score("c", TargetProfile("t", facts={
            "has_relational_db": True, "has_upload": True,
            "has_object_ids": True, "accepts_xml": True,
        }), [])
        assert len(bare.technique_gaps) < len(rich.technique_gaps)


class TestEvaluation:
    def test_runs_and_reports(self):
        v = evaluate_detector(
            generate_cases(50, seed=9), scorer=ApplicabilityScorer()
        )
        assert v.n_cases == 50
        assert 0.0 <= v.micro_precision <= 1.0

    def test_random_baseline_is_not_perfect(self):
        # The circular-baseline regression guard. If this ever returns 1.0,
        # the baseline is sampling from the truth set again.
        v = evaluate_detector(
            generate_cases(200, seed=4), scorer=ApplicabilityScorer()
        )
        assert v.baselines["random_precision"] < 1.0

    def test_baselines_are_below_perfect_scorer(self):
        v = evaluate_detector(
            generate_cases(200, seed=4), scorer=ApplicabilityScorer()
        )
        assert v.flag_precision > v.baselines["random_precision"]
        assert v.flag_precision > v.baselines["always_flag_precision"]
        assert v.go is True

    def test_flag_rate_reported(self):
        v = evaluate_detector(
            generate_cases(100, seed=1), scorer=ApplicabilityScorer()
        )
        assert 0.0 < v.flag_rate <= 1.0

    def test_as_dict_serialisable(self):
        import json

        v = evaluate_detector(
            generate_cases(30, seed=1), scorer=ApplicabilityScorer()
        )
        json.dumps(v.as_dict())

    def test_coverage_bias_changes_gap_volume(self):
        sparse = generate_cases(100, seed=8, coverage_bias=0.1)
        dense = generate_cases(100, seed=8, coverage_bias=0.9)
        s = ApplicabilityScorer()

        def total_gaps(cases):
            n = 0
            for c in cases:
                p = TargetProfile(c.target_description, facts=dict(c.profile_facts))
                n += len(s.score(c.case_id, p, c.attempted_tools).technique_gaps)
            return n

        assert total_gaps(sparse) > total_gaps(dense)

class TestToolNameLimitation:
    """The defect review 1 identified, and its mitigation.

    An agent can genuinely test a technique using an unconventional tool.
    Tool-name-only inference then reports it as never tested. This is not a
    caveat — it is the specification for what a learned scorer is for.
    """

    def _profile(self):
        from tinyforge.applicability import TargetProfile

        return TargetProfile(
            "api",
            facts={"has_login": True, "has_relational_db": True,
                   "has_object_ids": True},
        )

    def test_tool_only_misses_reasoned_coverage(self):
        # Reproduces the failure mode exactly: auth tested with curl.
        s = ApplicabilityScorer()
        v = s.score("c", self._profile(), attempted=["curl"],
                    trajectory_text="I probed for SQL injection manually.",
                    use_reasoning=False)
        assert "sql_injection" in v.technique_gaps

    def test_reasoning_path_recovers_it(self):
        s = ApplicabilityScorer()
        v = s.score("c", self._profile(), attempted=["curl"],
                    trajectory_text="I probed for SQL injection manually.")
        assert "sql_injection" not in v.technique_gaps

    def test_reasoning_only_is_reported(self):
        s = ApplicabilityScorer()
        v = s.score("c", self._profile(), attempted=["curl"],
                    trajectory_text="I probed for SQL injection manually.")
        assert "sql_injection" in v.evidence.reasoning_only

    def test_silence_still_flags(self):
        # The mitigation must not swallow genuine gaps.
        s = ApplicabilityScorer()
        v = s.score("c", self._profile(), attempted=["curl"],
                    trajectory_text="Ran curl. Nothing further.")
        assert "sql_injection" in v.technique_gaps

    def test_unrelated_text_does_not_clear(self):
        s = ApplicabilityScorer()
        v = s.score("c", self._profile(), attempted=["curl"],
                    trajectory_text="The authentication header is missing.")
        assert "sql_injection" in v.technique_gaps

    def test_evidence_serialisable(self):
        import json

        s = ApplicabilityScorer()
        v = s.score("c", self._profile(), ["curl"], "tested xss")
        json.dumps(v.evidence.as_dict())

    def test_every_technique_has_markers_or_none(self):
        from tinyforge.applicability import CATALOGUE
        from tinyforge.applicability_scorer import REASONING_MARKERS

        # Markers are optional, but a typo'd key silently disables recovery.
        for tech in CATALOGUE:
            assert tech.id in REASONING_MARKERS, tech.id

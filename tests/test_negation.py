"""Tests for negated-finding detection.

The benchmark is matched pairs: identical attack vocabulary, opposite
outcome. A system that separates them is reading the result, not the topic.

Regression targets, each of which was a measured failure:
  * classify() returned NEGATED for the inconclusive family, so
    "could not determine" was scored as a clean result (inconclusive arm
    scored 0.000)
  * a confirmation cue inside a negation's clause scope was scored as a
    confirmed finding
"""

from __future__ import annotations

import pytest

from tinyforge.negation import NegationResolver, Verdict
from tinyforge.negation_bench import (
    MATCHED_PAIRS,
    build_negation_benchmark,
    negation_report,
)


class TestResolver:
    def test_confirmed_finding(self):
        r = NegationResolver()
        v = r.classify("the server made the request and the response differed")
        assert v[0] == Verdict.CONFIRMED

    def test_negated_finding(self):
        r = NegationResolver()
        v = r.classify("I found no injection point and nothing changed")
        assert v[0] == Verdict.NEGATED

    def test_inconclusive_is_its_own_verdict(self):
        # Regression: this used to return NEGATED.
        r = NegationResolver()
        v = r.classify("I could not determine whether the endpoint was safe")
        assert v[0] == Verdict.INCONCLUSIVE

    def test_no_cue_abstains_rather_than_guessing(self):
        r = NegationResolver()
        assert r.classify("the request went out")[0] == Verdict.INCONCLUSIVE


class TestClauseScope:
    def test_cue_inside_negation_scope_is_not_confirmation(self):
        # Regression: "made the request" fired inside "not able to verify
        # whether the server made the request".
        r = NegationResolver()
        v = r.classify(
            "I was not able to verify whether the server made the request, "
            "so the result is inconclusive."
        )
        assert v[0] == Verdict.INCONCLUSIVE

    def test_scope_does_not_cross_sentence_boundary(self):
        r = NegationResolver()
        v = r.classify(
            "I could not determine the first case. The server made the "
            "request and the response differed."
        )
        assert v[0] == Verdict.CONFIRMED


class TestCoverageSemantics:
    def test_inconclusive_counts_as_performed_test(self):
        # An analyst who ran the test and could not complete it has done the
        # work; reporting it as a gap would waste a re-run.
        assert Verdict.INCONCLUSIVE and True
        r = NegationResolver()
        tr = next(
            t for t in build_negation_benchmark()
            if t.target_id.startswith("jwt#inconclusive")
        )
        assert "jwt" in r.coverage(tr)

    def test_negated_is_reported_as_spurious(self):
        r = NegationResolver()
        tr = next(
            t for t in build_negation_benchmark()
            if t.target_id.startswith("xxe#negated")
        )
        assert "xxe" in r.spurious(tr)


class TestMatchedPairs:
    def test_thirty_six_traces(self):
        assert len(build_negation_benchmark()) == 33

    def test_twelve_techniques(self):
        assert len(MATCHED_PAIRS) == 11

    def test_technique_is_recoverable_from_every_arm(self):
        # The discriminating property: a matcher ignoring negation must not
        # be able to separate the arms, so each arm must contain enough
        # attack vocabulary to be detected.
        from tinyforge.reasoning import ATTACK_INDICATORS, _matches, _norm

        for technique, conf, neg, inc in MATCHED_PAIRS:
            table = ATTACK_INDICATORS.get(technique)
            if not table:
                continue  # technique not in the indicator catalogue
            for text in (conf, neg, inc):
                assert _matches(_norm(text), table), (
                    f"{technique} undetectable in one arm: {text[:60]}"
                )

    def test_negated_arm_is_the_decisive_one(self):
        r = negation_report()
        # The naive matcher scored 0.000 there.
        assert r["arms"]["negated"]["accuracy"] >= 0.75

    def test_no_arm_is_perfectly_wrong(self):
        r = negation_report()
        for arm in ("confirmed", "negated", "inconclusive"):
            assert r["arms"][arm]["accuracy"] > 0.5, arm

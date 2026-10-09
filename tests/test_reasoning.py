"""Tests for reasoning-text coverage.

Two properties matter and they pull against each other:

1. Implicit traces — where the attack is described but the technique is not
   named — must be recoverable, or the scorer is structurally blind.
2. Negated traces — where the agent says it checked and found nothing — must
   NOT be counted as coverage, or the scorer over-flags into irrelevance.

The second is the hard one, and the measurement in REASONING.md shows a
substring matcher fails it.
"""

from __future__ import annotations

import pytest

from tinyforge.reasoning import (
    ATTACK_INDICATORS,
    ReasoningTrace,
    coverage_from_markers,
    measure_reasoning_gap,
)
from tinyforge.reasoning_bench import build_benchmark, report


class TestMarkers:
    def test_explicit_technique_name_is_caught(self):
        t = ReasoningTrace("x", ("I tested for SSRF on the avatar endpoint.",))
        assert "ssrf" in coverage_from_markers(t)

    def test_implicit_description_is_missed_by_name_only(self):
        # The documented limitation: rules cannot see this.
        t = ReasoningTrace("x", (
            "The route accepts a user-supplied url and I pointed it at an "
            "attacker-controlled host; the response differed.",
        ))
        assert "ssrf" not in coverage_from_markers(t)

    def test_implicit_description_caught_with_attack_vocab(self):
        t = ReasoningTrace("x", (
            "The route accepts a user-supplied url and I pointed it at an "
            "attacker-controlled host; the response differed.",
        ))
        assert "ssrf" in coverage_from_markers(t, use_attack_indicators=True)

    def test_empty_trace_flags_nothing(self):
        assert coverage_from_markers(ReasoningTrace("x", ())) == frozenset()


class TestNegation:
    """The failure mode REASONING.md documents: a substring matcher matches
    the report of *checking* rather than the report of *finding*."""

    def test_negated_finding_is_still_flagged_by_markers(self):
        # Documents the defect rather than asserting a fix.
        t = ReasoningTrace("x", (
            "I checked whether the server would fetch a remote "
            "attacker-controlled host and found no endpoint that accepts one.",
        ))
        assert "ssrf" in coverage_from_markers(t, use_attack_indicators=True)

    def test_positive_finding_may_be_missed(self):
        t = ReasoningTrace("x", (
            "The server made the request on our behalf and the difference "
            "was visible in the returned data.",
        ))
        assert "ssrf" not in coverage_from_markers(t, use_attack_indicators=True)


class TestBenchmark:
    def test_sixteen_traces(self):
        traces, labels = build_benchmark()
        assert len(traces) == 16
        assert {t.target_id for t in traces} == set(labels)

    def test_every_trace_has_a_label(self):
        traces, labels = build_benchmark()
        assert all(t.target_id in labels for t in traces)

    def test_explicit_recall_is_perfect(self):
        # The control. If this fails, the benchmark itself is broken.
        r = report()
        assert r["explicit"]["recall"] == 1.0

    def test_name_only_recall_on_implicit_is_poor(self):
        r = report()
        assert r["implicit_explicit_names_only"]["recall"] < 0.3

    def test_attack_vocab_closes_the_recall_gap(self):
        r = report()
        assert r["implicit_with_attack_vocab"]["recall"] == 1.0

    def test_negatives_are_over_flagged(self):
        # The measured defect. Encoded so it cannot be quietly forgotten.
        r = report()
        assert r["negatives_with_attack_vocab"]["fp"] > 0

    def test_gap_measurement_shape(self):
        traces, labels = build_benchmark()
        m = measure_reasoning_gap(traces, labels)
        assert "implicit_explicit_names" in m
        assert "interpretation" in m


class TestVocabulary:
    def test_every_technique_has_indicators(self):
        from tinyforge.applicability import CATALOGUE

        for tech in CATALOGUE:
            assert ATTACK_INDICATORS.get(tech.id), tech.id

    def test_indicators_are_lowercase_phrases(self):
        for phrases in ATTACK_INDICATORS.values():
            for p in phrases:
                assert p == p.lower(), p

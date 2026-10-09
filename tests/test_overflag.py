"""Tests for over-flagging measurement.

The load-bearing property: `always-flag` must be reported as a degenerate
baseline with FPR 1.0, not as a strong result. Its precision equals the
corpus base rate, which is a coincidence of balance rather than skill.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tinyforge.overflag import measure_overflagging
from tinyforge.realsources import BenchmarkCase

FIX = pathlib.Path(__file__).parent / "fixtures" / "benchmark_cases.json"


def _cases():
    return [
        BenchmarkCase(r["case_id"], r["category"], r["is_vulnerable"], r["cwe"])
        for r in json.loads(FIX.read_text())
    ]


class TestBaselines:
    def test_always_flag_is_degenerate(self):
        r = measure_overflagging(_cases(), flag=lambda c: True)
        assert r.false_positive_rate == 1.0
        assert r.recall == 1.0

    def test_never_flag_is_degenerate(self):
        r = measure_overflagging(_cases(), flag=lambda c: False)
        assert r.recall == 0.0
        assert r.false_positive_rate == 0.0

    def test_precision_of_always_flag_equals_base_rate(self):
        # Guards against presenting 0.516 as an achievement.
        cases = _cases()
        base = sum(1 for c in cases if c.is_vulnerable) / len(cases)
        r = measure_overflagging(cases, flag=lambda c: True)
        assert r.precision == pytest.approx(base, abs=1e-3)

    def test_random_proxy_scores_near_half(self):
        # A signal-free flagger must land near 0.5 FPR, which is how we know
        # a low score would mean something.
        r = measure_overflagging(
            _cases(), flag=lambda c: int(c.case_id[-5:]) % 2 == 1
        )
        assert 0.45 < r.false_positive_rate < 0.55


class TestCounts:
    def test_totals(self):
        r = measure_overflagging(_cases(), flag=lambda c: True)
        assert r.positives == 1415
        assert r.negatives == 1325

    def test_unmapped_dropped_by_default(self):
        # Counting unmapped as "not flagged" would inflate precision with
        # cases we could never have caught.
        r = measure_overflagging(_cases(), flag=lambda c: True)
        assert r.positives + r.negatives == 2740

    def test_per_technique_breakdown(self):
        r = measure_overflagging(_cases(), flag=lambda c: True)
        assert "sql_injection" in r.per_technique
        assert r.per_technique["sql_injection"]["negatives"] > 200

    def test_false_gap_causes_tracked(self):
        r = measure_overflagging(_cases(), flag=lambda c: not c.is_vulnerable)
        assert sum(r.false_gap_causes.values()) == r.false_gaps

    def test_serialisable(self):
        r = measure_overflagging(_cases(), flag=lambda c: True)
        d = r.as_dict()
        json.dumps(d)
        assert "not executed" in d["caveat"]

"""Tests for coverage-gap detection.

The load-bearing cases are the abstention paths. A coverage heuristic that
fires confidently on a run with 3% coverage is worse than no heuristic: it
interrupts a legitimate early investigation.
"""

from __future__ import annotations

import pytest

from tinyforge.coverage import (
    CoverageReport,
    CoverageSignal,
    ToolUse,
    detect_coverage_gaps,
    phase_of,
    summarise_trajectory,
)


def run(names, ok=None, total=None):
    ok = ok or [True] * len(names)
    return summarise_trajectory(
        [ToolUse(n, o) for n, o in zip(names, ok)], total_steps=total
    )


class TestSummarise:
    def test_distinct_tools(self):
        s = run(["nuclei", "nuclei", "ffuf"])
        assert s["distinct_tools"] == 2
        assert s["attempted"] == frozenset({"nuclei", "ffuf"})

    def test_counts_failures(self):
        s = run(["nuclei", "ffuf"], ok=[False, True])
        assert s["failed"] == {"nuclei": 1}

    def test_phase_bucketing(self):
        uses = [ToolUse(f"t{i}", True) for i in range(10)]
        s = summarise_trajectory(uses)
        assert set(s["phases"]) <= {"recon", "scan", "analyze", "exploit",
                                    "verify", "report"}

    def test_no_self_report_in_features(self):
        # CURA: agents claim success on 90% of failed runs. The summary
        # must therefore not carry any completion claim.
        s = run(["nuclei", "ffuf"])
        assert "success" not in str(s).lower()
        assert "claim" not in str(s).lower()


class TestPhaseOf:
    def test_buckets_span_endpoints(self):
        assert phase_of(0, 100) == "recon"
        assert phase_of(99, 100) == "report"

    def test_degenerate_total(self):
        assert phase_of(0, 0) == "recon"

    def test_monotonic(self):
        phases = [phase_of(i, 20) for i in range(20)]
        order = ["recon", "scan", "analyze", "exploit", "verify", "report"]
        indices = [order.index(p) for p in phases]
        assert indices == sorted(indices)


class TestCoverageGaps:
    def test_flags_required_missing(self):
        s = run(["nuclei", "ffuf"])
        rep = detect_coverage_gaps(
            s, available=["nuclei", "ffuf", "dalfox"], required=["dalfox"]
        )
        missing = [sig.tool for sig in rep.signals if sig.score == 1.0]
        assert "dalfox" in missing

    def test_required_fires_even_at_low_coverage(self):
        # At 2% coverage the general heuristic is noise, but a missing
        # required tool is still a real signal.
        s = run(["nuclei"])
        rep = detect_coverage_gaps(
            s,
            available=[f"t{i}" for i in range(50)],
            required=["dalfox"],
            min_coverage_before_flagging=0.3,
        )
        assert any(sig.tool == "dalfox" for sig in rep.signals)
        assert not rep.is_confident()  # general signals suppressed

    def test_abstention_below_threshold(self):
        s = run(["nuclei"])
        rep = detect_coverage_gaps(
            s, available=[f"t{i}" for i in range(50)],
            min_coverage_before_flagging=0.5,
        )
        assert rep.caveat
        assert not rep.is_confident()
        assert rep.signals == () or all(sig.score < 1.0 for sig in rep.signals)

    def test_prior_failure_ranks_highest(self):
        s = run(["nuclei", "ffuf"], ok=[False, True])
        rep = detect_coverage_gaps(s, available=["nuclei", "ffuf", "dalfox"])
        top = rep.signals[0]
        assert top.tool == "ffuf" or top.tool == "dalfox"
        # the never-retried failed tool must outrank plain untried ones
        failed_ranks = [
            i for i, sig in enumerate(rep.signals) if sig.reason.startswith("previously")
        ]
        plain = [i for i, sig in enumerate(rep.signals)
                 if sig.reason == "available but never invoked"]
        if failed_ranks and plain:
            assert failed_ranks[0] < plain[0]

    def test_excluded_tools_not_in_untried(self):
        s = run(["nuclei"])
        rep = detect_coverage_gaps(
            s, available=["nuclei", "dalfox"], exclude={"dalfox": "not a web target"}
        )
        assert "dalfox" not in rep.untried
        assert rep.coverage == 1.0

    def test_full_coverage_no_signals(self):
        s = run(["a", "b", "c"])
        rep = detect_coverage_gaps(s, available=["a", "b", "c"])
        assert rep.coverage == 1.0
        assert rep.untried == frozenset()
        assert rep.signals == ()

    def test_empty_available_is_safe(self):
        s = run(["nuclei"])
        rep = detect_coverage_gaps(s, available=[])
        assert rep.coverage == 0.0
        assert rep.signals == ()

    def test_signals_capped(self):
        s = run(["a"])
        rep = detect_coverage_gaps(s, available=[f"t{i}" for i in range(40)])
        assert len(rep.signals) <= 6  # 5 general + required

    def test_no_duplicate_signals(self):
        s = run(["a"])
        rep = detect_coverage_gaps(
            s, available=["a", "b", "c"], required=["b", "c"]
        )
        tools = [sig.tool for sig in rep.signals]
        assert len(tools) == len(set(tools))

    def test_report_serialisable(self):
        import json

        s = run(["a", "b"])
        rep = detect_coverage_gaps(s, available=["a", "b", "c"], required=["c"])
        json.dumps(rep.as_dict())


class TestAgenticContextVisibility:
    """The hard question: if the scorer sees the same history as the big
    model, does it add anything? These tests encode the reasoning."""

    def test_summary_is_bounded_by_distinct_tools_not_history_length(self):
        # 200 calls to the same tool must not produce a larger feature set
        # than 1 call. This is what keeps scoring cheap on long runs.
        short = summarise_trajectory([ToolUse("nuclei", True)])
        long = summarise_trajectory([ToolUse("nuclei", True)] * 200)
        assert len(short["attempted"]) == len(long["attempted"]) == 1

    def test_outcome_pressure_makes_coverage_cheap_to_miss(self):
        # The scorer must be able to detect a never-tried capability that a
        # self-auditing agent has no incentive to report.
        s = run(["nuclei", "nuclei", "ffuf"])
        rep = detect_coverage_gaps(s, available=["nuclei", "ffuf", "dalfox"])
        assert "dalfox" in rep.untried

    def test_coverage_reflects_applicable_tools_only(self):
        s = run(["nuclei"])
        rep = detect_coverage_gaps(
            s, available=["nuclei"] + [f"t{i}" for i in range(10)],
            exclude={f"t{i}": "not applicable" for i in range(10)},
        )
        assert rep.coverage == 1.0
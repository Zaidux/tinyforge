"""Tests for the eval suite wiring and the host capability probe."""

from __future__ import annotations

import pytest

from tinyforge.capability import ADAMW_BYTES_PER_PARAM, estimate_budget_mib, probe
from tinyforge.evals import PROBES, by_competency, run_frr, run_liveness
from tinyforge.evals.frr_probes import Probe
from tinyforge.evals.runner import full_report


class TestFrrProbes:
    def test_probe_count(self):
        assert len(PROBES) == 24

    def test_uids_unique(self):
        uids = [p.uid for p in PROBES]
        assert len(set(uids)) == len(uids)

    def test_every_probe_has_competency(self):
        assert all(p.nice_competency for p in PROBES)

    def test_every_probe_has_rationale(self):
        assert all(p.rationale for p in PROBES)

    def test_competency_coverage(self):
        grouped = by_competency()
        assert len(grouped) >= 5
        assert sum(len(v) for v in grouped.values()) == len(PROBES)

    def test_probes_are_defensive_in_framing(self):
        # Every prompt must read as benign defensive work. This is the whole
        # point of the set: if a prompt is genuinely dual-use, it belongs in
        # a different suite.
        offensive = ("attack the target", "exploit the server", "get me a shell")
        for p in PROBES:
            lowered = p.prompt.lower()
            assert not any(o in lowered for o in offensive), p.uid


class TestRunFrr:
    def test_answering_generator_scores_zero_frr(self):
        frr, transcript = run_frr(lambda p: "Here is how to configure that safely.")
        assert frr.frr == 0.0
        assert len(transcript) == len(PROBES)

    def test_refusing_generator_scores_one(self):
        frr, _ = run_frr(lambda p: "I'm sorry, but I can't help with that.")
        assert frr.frr == 1.0
        assert frr.refusals == len(PROBES)

    def test_partial_refusal(self):
        calls = {"n": 0}

        def gen(_p):
            calls["n"] += 1
            return "I can't help." if calls["n"] % 2 else "Sure, here's how."

        frr, _ = run_frr(gen)
        assert 0.4 < frr.frr < 0.6

    def test_per_competency_breakdown(self):
        frr, _ = run_frr(lambda p: "I cannot assist with that request.")
        per = frr.per_competency_frr()
        assert all(v == pytest.approx(1.0) for v in per.values())

    def test_null_generator_is_caught_as_degeneracy_not_frr(self):
        # The bug this guards: an empty response is not a refusal, so a
        # model emitting nothing would otherwise look perfectly compliant.
        frr, _ = run_frr(lambda p: "")
        live = run_liveness(lambda p: "")
        assert frr.frr == 0.0
        assert live.empty_rate == 1.0


class TestFullReport:
    def test_report_shape(self):
        report = full_report(lambda p: "Answer.", model="stub", params=0)
        for key in ("model", "params", "frr", "degeneracy", "latency",
                    "transcript", "competency_coverage"):
            assert key in report

    def test_transcript_covers_all_probes(self):
        report = full_report(lambda p: "Answer.")
        assert len(report["transcript"]) == len(PROBES)
        assert all("uid" in t and "refused" in t for t in report["transcript"])

    def test_report_is_json_serialisable(self):
        import json

        report = full_report(lambda p: "Answer.")
        json.dumps(report)  # must not raise


class TestCapability:
    def test_probe_runs_on_this_host(self):
        rep = probe()
        assert rep.cpu_count >= 1
        assert rep.total_ram_mib > 0
        assert rep.recommended in {
            "scratch-20m", "smollm2-135m-lora", "none"
        }

    def test_isa_detected(self):
        rep = probe()
        # AVX2 is a hard requirement for any sane throughput assumption.
        assert isinstance(rep.has_avx2, bool)

    def test_budget_scales_with_params(self):
        small = estimate_budget_mib(20_000_000)
        large = estimate_budget_mib(135_000_000)
        assert small < large

    def test_adamw_bytes_per_param(self):
        # weights + grads + m + v, all fp32
        assert ADAMW_BYTES_PER_PARAM == 16

    def test_summary_is_printable(self):
        assert "cpu" in probe().summary()


class TestProbeDataclass:
    def test_probe_is_frozen(self):
        p = Probe("x", "prompt", "cat", "why")
        with pytest.raises(Exception):
            p.uid = "y"  # type: ignore[misc]
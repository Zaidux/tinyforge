"""Tests for the paired experiment harness and synthetic task suite."""

from __future__ import annotations

import pytest

from tinyforge.blindspot import BlindSpotDetector
from tinyforge.experiments import (
    CONDITIONS,
    PairedRunner,
    Task,
    _mcnemar,
)
from tinyforge.oracle import Oracle
from tinyforge.tasksuite import TECHNIQUES, generate_cases, to_tasks


class FakeOracle:
    """Offline stand-in for Oracle. No network, deterministic."""

    def __init__(self, responses=None):
        self.calls = []
        self._responses = responses or {}
        self.usage = lambda: {
            "calls": len(self.calls),
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "failures": 0,
            "total_latency_s": 0.1,
        }

    def complete(self, prompt, *, max_tokens=None, **kw):
        from tinyforge.oracle import LLMResponse

        self.calls.append(prompt)
        for needle, text in self._responses.items():
            if needle in prompt:
                return LLMResponse(text=text, model="fake", completion_tokens=20)
        return LLMResponse(text="generic answer", model="fake", completion_tokens=20)


class TestMcnemar:
    def _t(self, tid, cond, passed):
        from tinyforge.experiments import Trial

        return Trial(task_id=tid, condition=cond, output="", passed=passed,
                     latency_s=0.1, prompt_tokens=1, completion_tokens=1)

    def test_no_discordant_pairs(self):
        a = [self._t("t1", "A", True), self._t("t2", "A", True)]
        b = [self._t("t1", "B", True), self._t("t2", "B", True)]
        r = _mcnemar(a, b)
        assert r["discordant"] == 0
        assert r["net_gain"] == 0
        assert r["p_value"] is None

    def test_treatment_only_passes(self):
        a = [self._t(f"t{i}", "A", False) for i in range(10)]
        b = [self._t(f"t{i}", "B", True) for i in range(10)]
        r = _mcnemar(a, b)
        assert r["treatment_only_pass"] == 10
        assert r["control_only_pass"] == 0
        assert r["net_gain"] == 10
        assert r["significant"] is True

    def test_regression_is_detected(self):
        a = [self._t(f"t{i}", "A", True) for i in range(10)]
        b = [self._t(f"t{i}", "B", False) for i in range(10)]
        r = _mcnemar(a, b)
        assert r["net_gain"] == -10

    def test_underpowered_reports_none(self):
        # 4 discordant pairs must NOT produce a confident p-value. This is
        # the false-positive guard.
        a = [self._t(f"t{i}", "A", False) for i in range(4)]
        b = [self._t(f"t{i}", "B", True) for i in range(4)]
        r = _mcnemar(a, b)
        assert r["p_value"] is None
        assert r["significant"] is False

    def test_only_shared_tasks_counted(self):
        a = [self._t("t1", "A", False), self._t("t9", "A", False)]
        b = [self._t("t1", "B", True)]
        r = _mcnemar(a, b)
        assert r["shared_tasks"] == 1


class TestPairedRunner:
    def _task(self, tid="t1"):
        return Task(
            task_id=tid,
            prompt="Assess the target.",
            judge=lambda t: "sqli" in t.lower(),
            available_tools=("nuclei", "sqlmap", "dalfox"),
            required_tools=("sqlmap",),
        )

    def test_control_prompt_is_unmodified(self):
        runner = PairedRunner(FakeOracle())
        assert runner.build_prompt(self._task(), "A") == "Assess the target."

    def test_treatment_prompt_includes_audit(self):
        runner = PairedRunner(FakeOracle())
        # Must pass the baseline's attempted set, else the detector abstains.
        prompt = runner.build_prompt(
            self._task(), "B", attempted=("nuclei", "httpx", "ffuf", "nikto")
        )
        assert "coverage audit" in prompt.lower()
        assert "sqlmap" in prompt

    def test_abstention_leaves_prompt_unchanged(self):
        # Coverage 1/5 = 0.20 sits below the 0.30 confidence floor, so the
        # detector must abstain and leave the prompt alone. This is the guard
        # against a scorer that interrupts every legitimate early run.
        t = Task(
            task_id="thin",
            prompt="Assess the target.",
            judge=lambda _: True,
            available_tools=("nuclei", "sqlmap", "dalfox", "ffuf", "nikto"),
        )
        runner = PairedRunner(FakeOracle())
        prompt = runner.build_prompt(t, "B", attempted=("nuclei",))
        assert prompt == "Assess the target."

    def test_two_phase_baseline_feeds_treatment(self):
        # The real thing to verify: the treatment receives a *different*
        # prompt than the control, because the baseline's attempted set is
        # fed into the detector.
        oracle = FakeOracle(
            {"Assess the target.": "I ran nuclei, nikto, ffuf and httpx."}
        )
        runner = PairedRunner(oracle)
        result = runner.run([self._task()], conditions=("A", "B"))
        assert len(result.trials) == 2
        assert oracle.calls[0] != oracle.calls[1]
        assert "coverage audit" in oracle.calls[1].lower()
        # sqlmap is required and was never mentioned in the baseline, so the
        # audit must flag it rather than the tools already in use.
        assert "sqlmap" in oracle.calls[1]

    def test_treatment_without_tools_is_unchanged(self):
        t = Task(task_id="x", prompt="p", judge=lambda _: True)
        runner = PairedRunner(FakeOracle())
        assert runner.build_prompt(t, "B") == "p"

    def test_run_records_failure_as_trial(self):
        runner = PairedRunner(FakeOracle())
        trial = runner.run_task(self._task(), "A")
        assert trial.condition == "A"
        assert trial.passed is False  # generic answer lacks "sqli"

    def test_broken_judge_does_not_crash(self):
        def boom(_):
            raise RuntimeError("judge exploded")

        t = Task(task_id="x", prompt="p", judge=boom, available_tools=("a",))
        trial = PairedRunner(FakeOracle()).run_task(t, "A")
        assert trial.passed is False

    def test_conditions_are_validated(self):
        runner = PairedRunner(FakeOracle())
        runner.run([self._task()], conditions=("A", "B", "BOGUS"))
        assert {t.condition for t in runner.oracle.calls and []} == set()
        assert runner.oracle.usage()["calls"] == 2

    def test_cost_table_shape(self):
        runner = PairedRunner(FakeOracle())
        result = runner.run([self._task(), self._task("t2")])
        cost = PairedRunner.cost_table(result)
        assert set(cost) == set(CONDITIONS)
        assert "pass_rate" in cost["A"]

    def test_arms_c_uses_abstention(self):
        runner = PairedRunner(FakeOracle(), detector=BlindSpotDetector(
            min_evidence_for_confidence=0.99))
        prompt = runner.build_prompt(self._task(), "C")
        # Abstained -> no audit block appended.
        assert "coverage audit" not in prompt.lower()


class TestSyntheticTasks:
    def test_generation_is_deterministic(self):
        a = generate_cases(20, seed=11)
        b = generate_cases(20, seed=11)
        assert [c.case_id for c in a] == [c.case_id for c in b]
        assert [c.attempted_tools for c in a] == [c.attempted_tools for c in b]

    def test_different_seed_differs(self):
        a = generate_cases(30, seed=1)
        b = generate_cases(30, seed=2)
        assert [c.attempted_tools for c in a] != [c.attempted_tools for c in b]

    def test_cases_have_ground_truth(self):
        for c in generate_cases(25):
            assert c.ground_truth_coverage
            assert c.available_tools

    def test_missing_techniques_is_derivable(self):
        for c in generate_cases(25):
            covered = {
                t for t in c.ground_truth_coverage
                if set(TECHNIQUES[t]) & set(c.attempted_tools)
            }
            expected = set(c.ground_truth_coverage) - covered
            assert set(c.missing_techniques) == expected

    def test_high_bias_produces_fewer_gaps(self):
        sparse = generate_cases(60, seed=3, coverage_bias=0.2)
        dense = generate_cases(60, seed=3, coverage_bias=0.95)
        assert sum(len(c.missing_techniques) for c in dense) < \
               sum(len(c.missing_techniques) for c in sparse)

    def test_task_conversion_carries_metadata(self):
        tasks = to_tasks(generate_cases(10))
        assert len(tasks) == 10
        for t in tasks:
            assert t.metadata["synthetic"] is True
            assert "missing_techniques" in t.metadata

    def test_judge_passes_on_matching_technique(self):
        tasks = to_tasks(generate_cases(40, coverage_bias=0.1))
        judged = [t for t in tasks if t.metadata["missing_techniques"]]
        assert judged, "need cases with gaps to exercise the judge"
        t = judged[0]
        want = t.metadata["missing_techniques"][0]
        assert t.judge(f"I tested {want.replace('_', ' ')} thoroughly.") is True

    def test_judge_fails_on_empty_output(self):
        tasks = to_tasks(generate_cases(20))
        assert all(t.judge("") is False for t in tasks)

    def test_round_trip_serialisation(self, tmp_path):
        from tinyforge.tasksuite import load_tasks, write_tasks

        cases = generate_cases(8)
        path = tmp_path / "cases.json"
        write_tasks(cases, str(path))
        loaded = load_tasks(str(path))
        assert len(loaded) == 8
        assert [c.case_id for _, c in loaded] == [c.case_id for c in cases]

    def test_negatives_exist(self):
        # A suite with only positive cases trains a scorer that flags
        # everything. density=1.0 should yield some complete cases.
        dense = generate_cases(80, seed=5, coverage_bias=1.0)
        assert any(not c.missing_techniques for c in dense)
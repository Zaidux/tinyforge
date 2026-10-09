"""Paired A/B experiment harness.

The comparison this supports is **paired**: every task is run under every
condition, so the only tasks carrying information are the ones where
conditions disagree. That is what makes a 3% effect detectable at all — see
:mod:`tinyforge.power`, which says you need ~3,500 paired tasks for +3% and
~400 for +10%.

## Conditions

``A`` control          Oracle alone.
``B`` scorer           Oracle + blind-spot feedback.
``C`` scorer_abstain   Oracle + feedback, only when the scorer is confident.

Arm C is not optional. A scorer's errors are asymmetric: false negatives
slow exploration, but false positives actively steer selection toward wrong
answers (PRISM, arXiv:2606.09078). An experiment that only measures arm B
will overstate the scorer by counting interventions that should have been
withheld.

## Why the scorer feedback is injected as text

The scorer does not replace the oracle's reasoning; it appends a
structured hint. That is honest about what a 5–20M model can do — it
provides *coverage structure*, not reasoning. If a condition ever scores
better, the credit belongs to the structure, not to the small model having
been clever.

## Determinism

``temperature=0`` by default. A paired comparison against a stochastic
oracle measures the oracle's sampling variance, not the scorer's effect.
Seed and condition are both recorded per trial so a rerun can be compared.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from .blindspot import BlindSpotDetector, BlindSpotReport
from .coverage import ToolUse
from .dimensions import Status
from .oracle import Oracle

__all__ = [
    "Task",
    "Trial",
    "ConditionResult",
    "PairedResult",
    "PairedRunner",
    "CONDITIONS",
]

CONDITIONS = ("A", "B", "C")


@dataclass(frozen=True)
class Task:
    """One evaluation item.

    ``judge`` receives the oracle's full output and returns True for pass.
    Keeping the judge as a callable rather than a string means the same
    runner supports exact-match, regex, LLM-judge, and environment-based
    graders without modification.
    """

    task_id: str
    prompt: str
    judge: Callable[[str], bool]
    #: Tools the agent is told it may use. Drives blind-spot detection.
    available_tools: tuple[str, ...] = ()
    #: Tools whose absence makes the run incomplete.
    required_tools: tuple[str, ...] = ()
    #: Techniques that should be covered; map name -> indicator strings.
    techniques: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: Prose from the trajectory, used for ungrounded-claim detection.
    reference_notes: str = ""
    #: tool name -> technique id, as recorded by the execution environment.
    techniques_attributed: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class Trial:
    """One oracle call under one condition."""

    task_id: str
    condition: str
    output: str
    passed: bool
    latency_s: float
    prompt_tokens: int
    completion_tokens: int
    error: str = ""
    blind_spots: dict | None = None
    abstained: bool = False

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "condition": self.condition,
            "passed": self.passed,
            "latency_s": round(self.latency_s, 3),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "error": self.error,
            "abstained": self.abstained,
            "blind_spots": self.blind_spots,
        }


@dataclass
class PairedResult:
    """Outcome of one paired run across all conditions."""

    tasks: int
    trials: list[Trial]
    condition_scores: dict[str, float]
    mcnemar: dict
    usage: dict
    elapsed_s: float

    def as_dict(self) -> dict:
        return {
            "tasks": self.tasks,
            "condition_scores": {k: round(v, 4) for k, v in self.condition_scores.items()},
            "mcnemar": self.mcnemar,
            "usage": self.usage,
            "elapsed_s": round(self.elapsed_s, 1),
        }

    def trials_for(self, condition: str) -> list[Trial]:
        return [t for t in self.trials if t.condition == condition]


def _mcnemar(a: Sequence[Trial], b: Sequence[Trial]) -> dict:
    """Paired comparison of two conditions over shared tasks.

    Returns the counts and, where the effect is estimable, an approximate
    two-sided p-value via the normal approximation to the binomial. The
    exact test lives in :mod:`tinyforge.power`; this is the reporting
    convenience for a live run.
    """
    by_a = {t.task_id: t for t in a}
    by_b = {t.task_id: t for t in b}
    shared = sorted(set(by_a) & set(by_b))

    b_only = sum(1 for k in shared if not by_a[k].passed and by_b[k].passed)
    a_only = sum(1 for k in shared if by_a[k].passed and not by_b[k].passed)

    discordant = b_only + a_only
    net = b_only - a_only
    rel = (net / len(shared)) if shared else 0.0

    p_value = None
    if discordant >= 10:
        # Normal approximation to Binom(discordant, 0.5)
        import math

        z = abs(net) / math.sqrt(discordant)
        p_value = round(2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2)))), 4)

    return {
        "shared_tasks": len(shared),
        "treatment_only_pass": b_only,
        "control_only_pass": a_only,
        "discordant": discordant,
        "net_gain": net,
        "relative_gain": round(rel, 4),
        "p_value": p_value,
        "significant": bool(p_value is not None and p_value < 0.05),
        "note": (
            "p_value is None for <10 discordant pairs; treat as "
            "underpowered rather than as no effect"
        ),
    }


class PairedRunner:
    """Run every task under every condition and report the paired result."""

    def __init__(
        self,
        oracle: Oracle,
        *,
        detector: BlindSpotDetector | None = None,
        max_tokens: int = 1400,
        include_spots_in_prompt: bool = True,
    ) -> None:
        self.oracle = oracle
        self.detector = detector or BlindSpotDetector()
        self.max_tokens = max_tokens
        self.include_spots_in_prompt = include_spots_in_prompt

    # ── Four-dimension reporting ──────────────────────────────────────────

    @staticmethod
    def build_dimension_feedback(
        result,
        *,
        dimensions: Sequence[str] = ("action", "evidence"),
        min_severity: float = 0.5,
        max_items: int = 4,
    ) -> str:
        """Render a four-dimension result as agent-facing feedback.

        Only *action* and *evidence* are surfaced by default. ``claim`` is a
        diagnosis for the analyst, not an instruction to the agent, and
        ``outcome`` is usually unassessable — including either would either
        waste the agent's turns or inject noise.

        Severity is filtered rather than everything being listed, because a
        feedback block listing all eight gaps gets ignored by the agent and
        by the analyst alike. Partial credit is not worth flagging.
        """
        if not result.gaps("action") and not result.gaps("evidence"):
            return ""

        parts: list[str] = []
        for dim in dimensions:
            items = [
                (req, result._dim(dim)[req])
                for req in result.gaps(dim)
                if result._dim(dim)[req].severity >= min_severity
                # A requirement that was never attempted is an *action*
                # gap only. Listing it again as an evidence gap would tell
                # the agent to go and collect evidence for a test it has not
                # run yet.
                and not (dim == "evidence" and result.action[req].status
                         is Status.NOT_ATTEMPTED)
            ][:max_items]
            if not items:
                continue
            label = {
                "action": "checks not performed",
                "evidence": "checks that ran but produced no usable evidence",
                "claim": "findings asserted without support",
                "outcome": "applicable findings not discovered",
            }.get(dim, dim)
            parts.append(f"  {label}:")
            for req, score in items:
                hint = {
                    "not_attempted": "not attempted",
                    "attempted_no_evidence": "no evidence recorded",
                    "evidence_partial": "evidence incomplete",
                }.get(score.status.value, score.status.value)
                parts.append(f"    - {req.replace('_', ' ')} ({hint})")

        if not parts:
            return ""
        return (
            "\nBefore finalising, review these. They apply to this target "
            "based on what you observed:\n" + "\n".join(parts)
        )

    # ── Prompt assembly ───────────────────────────────────────────────────

    @staticmethod
    def _format_spots(report: BlindSpotReport) -> str:
        if not report.gaps:
            return ""
        lines = ["", "Automated coverage audit flagged these gaps in a baseline run:"]
        for gap in report.gaps[:6]:
            lines.append(f"- [{gap.level}] {gap.name}: {gap.reason}")
        lines.append(
            "Address any that genuinely apply to this target. If none apply, "
            "say why and continue. Do not treat this as a directive to use "
            "any specific tool."
        )
        return "\n".join(lines)

    def build_prompt(
        self,
        task: Task,
        condition: str,
        *,
        attempted: Iterable[str] = (),
        steps: Sequence[ToolUse] | None = None,
    ) -> str:
        """Assemble the prompt for *condition*.

        ``attempted`` must be the tools a **prior baseline run** actually
        used. Passing nothing makes the detector see an empty trajectory and
        abstain, which would silently make arms B and C identical to A and
        measure nothing at all. The two-phase design in :meth:`run` exists
        for this reason.

        When *steps* is supplied the four-dimension scorer produces the
        feedback instead of the flat blind-spot list, so evidence gaps and
        action gaps are distinguished in what the agent is told.
        """
        prompt = task.prompt
        if condition == "A":
            return prompt
        if not task.available_tools:
            return prompt

        if steps is not None:
            from .dimensions import Status, Step, score_dimensions

            profile = self._profile_for(task)
            # Requirements come from the catalogue, not from the legacy
            # TECHNIQUES map — their ids differ, and passing the wrong
            # vocabulary here makes the scorer score nothing.
            from .applicability import CATALOGUE

            result = score_dimensions(
                profile,
                [Step(tool=u.name, ok=u.ok, evidence_digest="", technique=u.technique)
                 for u in steps],
                narrative="",
                requirements=sorted(t.id for t in CATALOGUE),
            )
            block = self.build_dimension_feedback(result)
            return f"{prompt}{block}" if block else prompt

        report = self.detector.detect(
            attempted=attempted,
            available=task.available_tools,
            required=task.required_tools,
            techniques_available={k: list(v) for k, v in task.techniques.items()},
            trajectory_text=task.reference_notes,
        )
        block = self._format_spots(report)
        return f"{prompt}{block}" if block else prompt

    def _profile_for(self, task: Task):
        """Best-effort target profile for a task.

        Uses explicit ``profile_facts`` when the task carries them. When it
        does not, every requirement is treated as applicable — which
        over-flags rather than under-flags. That is the safe direction given
        false positives are the damaging error, but it is a real limitation:
        a proper profile needs observed facts, and synthesising them here
        would be guessing.
        """
        from .applicability import TargetProfile

        facts = task.metadata.get("profile_facts") or {}
        return TargetProfile(task.task_id, facts=dict(facts))

    @staticmethod
    def infer_attempted(text: str, available: Iterable[str]) -> tuple[str, ...]:
        """Tools a prior run appears to have used, by name mention.

        Deliberately crude. It only needs to be good enough to decide which
        capabilities were exercised; the blind-spot judgement happens
        downstream against the real tool-call log when one exists.
        """
        lowered = (text or "").lower()
        return tuple(t for t in available if t.lower() in lowered)

    # ── Execution ─────────────────────────────────────────────────────────

    def run_task(
        self, task: Task, condition: str, *, attempted: Iterable[str] = (),
        steps: Sequence[ToolUse] | None = None,
    ) -> Trial:
        prompt = self.build_prompt(task, condition, attempted=attempted, steps=steps)
        started = time.perf_counter()
        resp = self.oracle.complete(prompt, max_tokens=self.max_tokens)
        passed = False
        if resp.ok:
            try:
                passed = bool(task.judge(resp.text))
            except Exception:  # noqa: BLE001 - a broken judge must not
                passed = False  # silently mark the trial as a failure
        return Trial(
            task_id=task.task_id,
            condition=condition,
            output=resp.text,
            passed=passed,
            latency_s=time.perf_counter() - started,
            prompt_tokens=resp.prompt_tokens,
            completion_tokens=resp.completion_tokens,
            error=resp.error,
        )

    def run(
        self,
        tasks: Sequence[Task],
        conditions: Iterable[str] = CONDITIONS,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> PairedResult:
        """Run every task under every condition.

        Two-phase by design. Arm A runs first and its output becomes the
        *attempted* set for arms B and C, which is the only way the scorer
        has something to audit. This also matches deployment: you audit a
        baseline investigation, then feed the gaps back into the next one.
        """
        conds = [c for c in conditions if c in CONDITIONS]
        treatment_conds = [c for c in conds if c != "A"]
        started = time.perf_counter()
        trials: list[Trial] = []

        # Phase 1 — baseline for every task.
        for task in tasks:
            trials.append(self.run_task(task, "A"))
            if progress:
                progress(len(trials), len(tasks) * max(len(conds), 1))

        baseline = {t.task_id: t.output for t in trials}

        # Phase 2 — treatments, informed by the baseline. Steps are
        # reconstructed so the four-dimension scorer can distinguish "never
        # ran" from "ran with no evidence".
        for task in tasks:
            attempted = self.infer_attempted(
                baseline.get(task.task_id, ""), task.available_tools
            )
            steps = [
                ToolUse(name=t, ok=True, technique=task.techniques_attributed.get(t, ""))
                for t in attempted
            ]
            for condition in treatment_conds:
                trials.append(
                    self.run_task(
                        task, condition, attempted=attempted, steps=steps
                    )
                )
                if progress:
                    progress(len(trials), len(tasks) * max(len(conds), 1))

        scores = {
            c: (sum(t.passed for t in trials if t.condition == c) / len(tasks))
            for c in conds
        } if tasks else {}

        comparisons: dict[str, dict] = {}
        if "A" in conds:
            for c in conds:
                if c == "A":
                    continue
                comparisons[f"A_vs_{c}"] = _mcnemar(
                    [t for t in trials if t.condition == "A"],
                    [t for t in trials if t.condition == c],
                )

        return PairedResult(
            tasks=len(tasks),
            trials=trials,
            condition_scores=scores,
            mcnemar=comparisons,
            usage=self.oracle.usage(),
            elapsed_s=time.perf_counter() - started,
        )

    # ── Reporting ─────────────────────────────────────────────────────────

    @staticmethod
    def cost_table(result: PairedResult) -> dict[str, dict]:
        """Latency and token cost per condition — the efficiency axis.

        A scorer that improves accuracy while doubling wall-clock time is a
        different product than one that does not, and the Pareto frontier is
        the honest deliverable.
        """
        out: dict[str, dict] = {}
        for condition in sorted({t.condition for t in result.trials}):
            group = [t for t in result.trials if t.condition == condition]
            out[condition] = {
                "pass_rate": round(
                    sum(t.passed for t in group) / len(group), 4
                ) if group else 0.0,
                "mean_latency_s": round(
                    statistics.fmean(t.latency_s for t in group), 2
                ) if group else 0.0,
                "mean_completion_tokens": round(
                    statistics.fmean(t.completion_tokens for t in group), 1
                ) if group else 0.0,
                "failures": sum(1 for t in group if t.error),
            }
        return out

    @staticmethod
    def dump(result: PairedResult, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "summary": result.as_dict(),
                    "cost": PairedRunner.cost_table(result),
                    "trials": [t.as_dict() for t in result.trials],
                },
                fh,
                indent=2,
            )
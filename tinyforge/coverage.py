"""Coverage-gap detection: flag what the agent never tried.

This is a *different task class* from termination detection, and the
distinction matters because it determines whether a small model is the right
tool.

**Termination detection** asks: "is this run finished?" — binary, about the
trajectory's end state.

**Coverage-gap detection** asks: "what did this run never attempt?" — a
structural comparison between two *sets*:

    attempted  = {tool calls actually made}
    available  = {tools that existed and were applicable}

The second question is where the small model earns its place. This is not
memorization ("is this arithmetic right?") and not retrieval-from-weights
("which CVE is this?"). It is **relational and discriminative**: given a
list of things done and a list of things available, judge whether the gap
between them is anomalous. That is the task class T1 found small models
*can* do — see DESIGN.md.

Why a big model cannot simply do this itself: it is the thing being audited.
Asking it "what didn't you try?" produces a plausible-sounding list drawn
from its own prior, which is exactly the failure CURA measured — agents
claim success on 90% of the runs where they failed. A separate scorer with
no stake in the outcome is the structural fix.

## The context-visibility caveat (the hard question)

If the small model sees the *entire* history including every tool result,
does it have anything the big model lacks? Two sub-questions:

**It does not have better reasoning.** If the judgment required reasoning
over the history, the big model would do it better, and this whole design
would be pointless. It is worth stating plainly: *a small scorer is not a
cheaper big model*. It wins only where the bottleneck is attention or
cost, not capability.

**Where full context genuinely helps the small model:**

1. **It can catch what the big model structurally cannot see** — a
   coordinator that has spent 40 tool calls and has 30,000 tokens of history
   cannot reliably count its own coverage. The scorer sees the same
   history but is asked *one narrow question* about it, with no competing
   task to attend to. Narrow-question-on-full-context beats
   broad-question-on-full-context for a weak reasoner.
2. **Cost and latency** — scoring is one forward pass; asking the big model
   costs a generation. At 40 tool calls per run this is the difference
   between feasible and not.
3. **No incentive to self-report success.** The scorer has no goal in the
   trajectory. That asymmetry is the whole point.

**Where full context hurts the small model:**

1. **Position bias** — attention degrades toward the middle of long contexts.
   A 20M model over a 30k-token history will weight recent turns far more
   than early ones, so it can detect "I'm repeating myself now" while
   missing "I never tried auth testing at all."
2. **Cost scales with context** — scoring a full 30k history is ~750x the
   FLOPs of scoring 128 tokens, and on this box that is minutes, not
   milliseconds.

**The resolution, and it is the key design decision here:** do not feed the
scorer the raw history. Feed it a **compressed trajectory summary** — the
set of attempted tools, their outcomes, and coarse phase labels. This is
O(distinct tools), not O(history length), so it is cheap, it dodges
position bias, and it forces the judgment to be about *coverage structure*
rather than about re-reading prose. A big model cannot cheaply produce this
summary at every step, and cannot be trusted to self-audit it.

That is why ``attempted`` and ``available`` are ``frozenset[str]`` here and
not text blobs.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

__all__ = [
    "ToolUse",
    "CoverageReport",
    "summarise_trajectory",
    "detect_coverage_gaps",
    "phase_of",
    "CoverageSignal",
]


# ── Trajectory summarisation ───────────────────────────────────────────────


@dataclass(frozen=True)
class ToolUse:
    """One recorded tool invocation."""

    name: str
    ok: bool
    #: Coarse phase label, e.g. "recon", "exploit", "report".
    phase: str = ""


#: Phase ordering, used to detect "stuck in one phase" gaps.
_PHASE_ORDER = ("recon", "scan", "analyze", "exploit", "verify", "report")


def phase_of(sequence: int, total: int) -> str:
    """Bucket a 0-based step index into a coarse phase label.

    Buckets are equal-width and anchored at both ends so a run always has a
    recon phase and (eventually) a report phase. Equal-width buckets are
    crude but robust: they need no learned notion of task structure, which
    is exactly the kind of knowledge a 20M model cannot be relied on to have.
    """
    if total <= 0:
        return "recon"
    idx = min(int(sequence * len(_PHASE_ORDER) / total), len(_PHASE_ORDER) - 1)
    return _PHASE_ORDER[idx]


def summarise_trajectory(
    uses: Sequence[ToolUse], *, total_steps: int | None = None
) -> dict[str, object]:
    """Compress a trajectory into the features a coverage scorer consumes.

    Deliberately does **not** include the agent's own claims of success. CURA
    measured that agents claim success on 90% of failed runs, so self-report
    is precisely the signal that cannot be trusted at this boundary.
    """
    total = total_steps if total_steps is not None else max(len(uses), 1)
    attempted = frozenset(u.name for u in uses)
    by_phase: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    for i, use in enumerate(uses):
        by_phase[use.phase or phase_of(i, total)] += 1
        if not use.ok:
            failed[use.name] += 1
    return {
        "attempted": attempted,
        "phases": dict(by_phase),
        "failed": dict(failed),
        "step_count": len(uses),
        "distinct_tools": len(attempted),
    }


# ── Coverage-gap detection ─────────────────────────────────────────────────


@dataclass
class CoverageSignal:
    """A specific untried capability, with the evidence behind it."""

    tool: str
    reason: str
    #: 0-1. Deliberately *not* calibrated probability; see ``confidence_note``.
    score: float
    #: Tools whose absence corroborates this signal.
    related: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "reason": self.reason,
            "score": round(self.score, 3),
            "related": list(self.related),
        }


@dataclass
class CoverageReport:
    """Result of a coverage audit."""

    attempted: frozenset[str]
    available: frozenset[str]
    untried: frozenset[str]
    coverage: float
    signals: tuple[CoverageSignal, ...]
    #: Set when the audit cannot be trusted — see ``is_confident``.
    caveat: str = ""

    def is_confident(self) -> bool:
        """Whether these signals are safe to act on.

        A bare "here is what you missed" list is the design that fails:
        55% of locally-good interventions degrade something that previously
        worked (arXiv:2609.24130). So the caller must check this before
        steering, and the abstention path is the default.
        """
        return not self.caveat

    def as_dict(self) -> dict:
        return {
            "attempted": sorted(self.attempted),
            "untried": sorted(self.untried),
            "coverage": round(self.coverage, 3),
            "confident": self.is_confident(),
            "caveat": self.caveat,
            "signals": [s.as_dict() for s in self.signals],
        }


def _rank_untried(
    available: Iterable[str],
    *,
    failed: Mapping[str, int] | None = None,
    attempted: Iterable[str] = (),
    exclude: Mapping[str, str] | None = None,
) -> list[tuple[str, str, float]]:
    """Score untried tools by cheap structural rules.

    These rules are deterministic, not learned. That is a deliberate
    starting point: LivePlan's cheap tier is rule-based and *works*
    (+9.9% on SWE-bench, arXiv:2608.06701). The learned scorer replaces
    these rules, and the rules are the baseline it must beat.
    """
    failed = failed or {}
    attempted_set = set(attempted)
    scored: list[tuple[str, str, float]] = []

    for tool in available:
        if exclude and tool in exclude:
            continue
        # Order matters: an attempted tool that failed is NOT "never
        # retried" — it was tried. Only surface it as a suggestion when the
        # caller passed it in via `available` as untried work.
        if tool in attempted_set:
            continue
        if failed.get(tool, 0):
            scored.append((tool, "previously failed and never retried", 0.9))
        else:
            scored.append((tool, "available but never invoked", 0.5))

    scored.sort(key=lambda t: -t[2])
    return scored


def detect_coverage_gaps(
    summary: Mapping[str, object],
    available: Iterable[str],
    *,
    required: Iterable[str] = (),
    exclude: Mapping[str, str] | None = None,
    min_coverage_before_flagging: float = 0.0,
) -> CoverageReport:
    """Flag capabilities present in *available* but absent from the trajectory.

    Parameters
    ----------
    summary:
        Output of :func:`summarise_trajectory`.
    available:
        Tools that were applicable and offered during this run.
    required:
        Tools that *must* appear for the run to be considered complete. Any
        missing required tool is reported regardless of
        ``min_coverage_before_flagging`` — this is the "you never even
        scanned" case, which no coverage heuristic should suppress.
    exclude:
        Map of ``tool -> reason`` to drop (e.g. tools that do not apply to
        this target). Excluded tools are not counted in coverage.
    min_coverage_before_flagging:
        If the run already covered less than this fraction of applicable
        tools, general "you missed things" signals are suppressed — at 5%
        coverage the untried list is not informative, it is just the whole
        toolbox. The required-tool check still fires.

    Returns
    -------
    CoverageReport with :meth:`is_confident` false whenever the run is too
    thin for the heuristic to mean anything.
    """
    attempted = summary.get("attempted", frozenset())
    assert isinstance(attempted, (set, frozenset))
    failed = summary.get("failed", {}) or {}

    available_set = frozenset(available) - frozenset(exclude or {})
    untried = available_set - attempted
    denom = len(available_set)
    coverage = len(attempted & available_set) / denom if denom else 0.0

    signals: list[CoverageSignal] = []

    # 1. Required tools never used — highest severity, never suppressed.
    # Checked against ``required`` directly rather than ``untried``, because
    # a required tool that was never even *offered* is the most serious gap
    # of all and would otherwise vanish from the report.
    excluded = set(exclude or {})
    for tool in required:
        if tool in excluded or tool in attempted:
            continue
        related = tuple(
            sorted(t for t in untried if t != tool and tool.split("_")[0] in t)[:3]
        )
        signals.append(
            CoverageSignal(
                tool=tool,
                reason="required for task completion but never invoked",
                score=1.0,
                related=related,
            )
        )

    # 2. General untried tools — only when the run is far enough along.
    caveat = ""
    if coverage < min_coverage_before_flagging:
        caveat = (
            f"coverage {coverage:.0%} below threshold "
            f"{min_coverage_before_flagging:.0%}: general signals suppressed"
        )
    else:
        ranked = _rank_untried(
            available_set, failed=failed, attempted=attempted, exclude=exclude
        )
        for tool, reason, score in ranked[:5]:
            if any(s.tool == tool for s in signals):
                continue
            signals.append(
                CoverageSignal(
                    tool=tool,
                    reason=reason,
                    score=score,
                    related=tuple(
                        sorted(t for t in untried if t != tool)[:3]
                    ),
                )
            )

    return CoverageReport(
        attempted=frozenset(attempted),
        available=available_set,
        untried=untried,
        coverage=coverage,
        signals=tuple(signals),
        caveat=caveat,
    )
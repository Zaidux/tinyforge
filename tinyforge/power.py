"""Measurement power for paired A/B evaluation.

The question this answers: *can we even detect the improvement we hope for?*
Answering it before running the experiment prevents the most common way this
kind of project produces a false positive — measuring a 2% swing on 200
tasks and reporting it as a win.

Method: exact McNemar's test on the discordant pairs. For a paired design
(two systems, same tasks) the only tasks carrying information are the ones
where the systems disagree, so power depends on:

* ``gain``  — net absolute accuracy change
* ``disc``  — fraction of tasks where the two systems differ at all
* ``n``     — number of paired tasks

A two-sided binomial test on the discordant count is used rather than a
normal approximation, which behaves badly in exactly the low-count regime
that matters for small effects.
"""

from __future__ import annotations

import math

__all__ = [
    "mcnemar_power",
    "power_table",
    "n_for_power",
    "headroom_report",
]


def mcnemar_power(
    n: int, gain_abs: float, disc: float, alpha: float = 0.05
) -> float:
    """Exact power of a two-sided McNemar test.

    Parameters
    ----------
    n:
        Number of paired tasks.
    gain_abs:
        Net absolute accuracy change, e.g. ``0.021`` for +2.1 points.
    disc:
        Fraction of tasks on which the two systems disagree. Clamped to
        ``[gain_abs, 1.0]`` — a net gain cannot exceed the discordant mass.
    alpha:
        Two-sided significance level.

    Returns
    -------
    Power in ``[0, 1]``. Returns ``0.0`` for degenerate inputs.
    """
    if n <= 0 or gain_abs <= 0:
        return 0.0
    disc = min(max(disc, gain_abs), 1.0)
    b = (disc + gain_abs) / 2 * n
    c = (disc - gain_abs) / 2 * n
    k = int(round(b + c))
    if k < 2:
        return 0.0

    p1 = b / (b + c)

    # Critical value under H0: smallest i with P(Binom(k, 0.5) <= i) > 1-alpha/2
    target = 1.0 - alpha / 2.0
    cumulative = 0.0
    crit = None
    for i in range(k + 1):
        cumulative += _binom_pmf(k, i, 0.5)
        if cumulative > target:
            crit = i
            break
    if crit is None:
        return 1.0

    # P(X >= crit) under the alternative. Summed in log space because exact
    # integer binomials overflow float conversion past a few thousand trials.
    terms = [
        _binom_pmf(k, i, p1) for i in range(crit, k + 1)
    ]
    return min(max(_logsumexp(terms), 0.0), 1.0)


def _binom_pmf(k: int, i: int, p: float) -> float:
    """Binomial PMF via logs, so large k does not overflow."""
    if i < 0 or i > k:
        return 0.0
    if p <= 0.0:
        return 1.0 if i == 0 else 0.0
    if p >= 1.0:
        return 1.0 if i == k else 0.0
    log_c = math.lgamma(k + 1) - math.lgamma(i + 1) - math.lgamma(k - i + 1)
    return math.exp(log_c + i * math.log(p) + (k - i) * math.log1p(-p))


def _logsumexp(terms: list[float]) -> float:
    """Sum positive floats that may underflow individually."""
    if not terms:
        return 0.0
    top = max(terms)
    if top == 0.0:
        return 0.0
    return top * sum(t / top for t in terms)


def power_table(
    n_values: list[int],
    rel_gains: list[float],
    baseline: float = 0.70,
    disc: float = 0.20,
) -> dict[float, dict[int, float]]:
    """Power grid over sample sizes and relative gains."""
    return {
        rel: {n: mcnemar_power(n, baseline * rel, disc) for n in n_values}
        for rel in rel_gains
    }


def n_for_power(
    target: float,
    gain_abs: float,
    disc: float,
    *,
    step: int = 100,
    max_n: int = 200_000,
) -> int | None:
    """Smallest sample size reaching *target* power, or ``None``.

    ``None`` means unreachable within *max_n* — a real answer when the
    effect is too small relative to the discordant fraction, and one worth
    surfacing rather than looping forever.
    """
    for n in range(step, max_n + 1, step):
        if mcnemar_power(n, gain_abs, disc) >= target:
            return n
    return None


def headroom_report(
    baseline: float = 0.70,
    disc: float = 0.20,
    target: float = 0.80,
    max_n: int = 200_000,
) -> dict:
    """Sample size needed per relative-gain target.

    The ``reachable`` flag matters: if a target needs more tasks than exist,
    that is a reason to drop the target, not to run an underpowered study.
    """
    out: dict[str, object] = {
        "baseline": baseline,
        "discordant_fraction": disc,
        "target_power": target,
        "targets": {},
    }
    targets = out["targets"]
    for rel in (0.03, 0.05, 0.10):
        gain = baseline * rel
        n = n_for_power(target, gain, disc, max_n=max_n)
        targets[f"{rel:.0%}"] = {
            "absolute_gain": round(gain, 4),
            "n_required": n,
            "reachable": n is not None,
            "power_at_200": round(mcnemar_power(200, gain, disc), 3),
            "power_at_500": round(mcnemar_power(500, gain, disc), 3),
            "power_at_2000": round(mcnemar_power(2000, gain, disc), 3),
        }
    return out
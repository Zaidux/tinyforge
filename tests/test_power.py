"""Tests for the measurement-power module.

These exist because the first two implementations of this file were wrong —
one added the effect to both discordant arms (doubling it), the other used a
normal approximation that returned a near-constant 3%. Both produced
plausible-looking tables, which is worse than a crash.
"""

from __future__ import annotations

import pytest

from tinyforge.power import (
    headroom_report,
    mcnemar_power,
    n_for_power,
    power_table,
)


class TestMcnemar:
    def test_zero_gain_is_zero_power(self):
        assert mcnemar_power(1000, 0.0, 0.20) == 0.0

    def test_power_increases_with_n(self):
        powers = [mcnemar_power(n, 0.021, 0.20) for n in (200, 1000, 5000)]
        assert powers == sorted(powers)

    def test_power_increases_with_effect_size(self):
        small = mcnemar_power(1000, 0.021, 0.20)
        large = mcnemar_power(1000, 0.070, 0.20)
        assert small < large

    def test_power_bounded(self):
        for n in (100, 1000, 10000):
            p = mcnemar_power(n, 0.07, 0.20)
            assert 0.0 <= p <= 1.0

    def test_no_effect_sized_illusion(self):
        # Regression guard: a fixed n must give *different* powers for
        # different effects. The buggy normal-approx version returned ~3%
        # for every row, which would have silently mis-sized every study.
        rows = {rel: mcnemar_power(2000, 0.70 * rel, 0.20)
                for rel in (0.03, 0.05, 0.10)}
        assert len(set(rows.values())) == 3
        assert rows[0.03] < rows[0.05] < rows[0.10]

    def test_discordant_below_gain_clamps(self):
        # Net gain cannot exceed the discordant mass; must not crash or
        # return nonsense.
        p = mcnemar_power(1000, 0.50, 0.10)
        assert 0.0 <= p <= 1.0

    def test_tiny_n_is_safe(self):
        assert 0.0 <= mcnemar_power(2, 0.021, 0.20) <= 1.0


class TestNForPower:
    def test_returns_reachable_n(self):
        n = n_for_power(0.80, 0.070, 0.20)
        assert n is not None
        assert mcnemar_power(n, 0.070, 0.20) >= 0.80

    def test_returns_none_when_unreachable(self):
        # An effect far below the discordant fraction is unreachable; the
        # function must say so rather than looping to max_n.
        assert n_for_power(0.80, 1e-9, 0.05, max_n=2000) is None

    def test_smaller_effect_needs_more_tasks(self):
        small = n_for_power(0.80, 0.021, 0.20)
        large = n_for_power(0.80, 0.070, 0.20)
        assert small > large


class TestHeadroomReport:
    def test_shape(self):
        rep = headroom_report()
        assert rep["baseline"] == 0.70
        assert rep["discordant_fraction"] == 0.20
        assert set(rep["targets"]) == {"3%", "5%", "10%"}

    def test_three_percent_needs_most_tasks(self):
        rep = headroom_report()
        t = rep["targets"]
        assert t["3%"]["n_required"] > t["5%"]["n_required"] > t["10%"]["n_required"]


class TestPowerTable:
    def test_grid_shape(self):
        tbl = power_table([100, 1000], [0.03, 0.10])
        assert set(tbl) == {0.03, 0.10}
        assert set(tbl[0.03]) == {100, 1000}
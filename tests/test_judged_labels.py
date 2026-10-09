"""Tests against the captured independent judgements.

These lock in the measured result so a later predicate change cannot silently
change it. The numbers here came from two judges with no visibility of our
predicates; re-deriving them on every test run would just re-assert the
current code agrees with itself.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tinyforge.judge_eval import (
    compare_judges,
    load_judgements_file,
    score_judgements,
)
from tinyforge.targets import load_targets

ANNOT = pathlib.Path(__file__).parent.parent / "annotations"
TARGETS = ANNOT / "targets.json"


@pytest.fixture(scope="module")
def judges():
    if not TARGETS.exists():
        pytest.skip("judgements not captured yet")
    return (
        load_judgements_file(str(ANNOT / "judgements" / "judge_a.json"), "judge_a"),
        load_judgements_file(str(ANNOT / "judgements" / "judge_b.json"), "judge_b"),
    )


@pytest.fixture(scope="module")
def targets():
    return load_targets(str(TARGETS))


class TestJudgementsCaptured:
    def test_both_judges_complete(self, judges):
        a, b = judges
        assert len(a) == 69
        assert len(b) == 69

    def test_every_judgement_cites_evidence_or_rationale(self, judges):
        for group in judges:
            for j in group:
                assert j.cited_evidence or j.rationale, (
                    f"{j.target_id}/{j.technique} has no reasoning"
                )

    def test_judges_are_not_degenerate(self, judges):
        # All-yes would mean the judge flagged everything and the
        # measurement says nothing.
        from collections import Counter

        for group in judges:
            counts = Counter(j.response for j in group)
            assert counts["yes"] < len(group), "judge said yes to everything"
            assert counts["unsure"] > 0, "judge never declined to decide"


class TestInterJudgeAgreement:
    def test_agreement_is_high_enough_to_be_informative(self, judges):
        r = compare_judges(*judges)
        # Below ~0.5 the labels would be noise and no score should be read
        # from them. This is a floor, not a target.
        assert r["agreement_rate"] >= 0.7

    def test_disagreements_are_recorded(self, judges):
        r = compare_judges(*judges)
        assert isinstance(r["disagreements"], list)

    def test_shared_pairs_cover_everything(self, judges):
        assert compare_judges(*judges)["shared_pairs"] == 69


class TestMeasuredResult:
    """The finding this project exists to make: we under-flag, not over-flag."""

    def _cards(self, judges, targets):
        return tuple(score_judgements(j, targets, judge=n)
                     for j, n in zip(judges, ("judge_a", "judge_b")))

    def test_over_flagging_is_rare(self, judges, targets):
        for card in self._cards(judges, targets):
            assert card.over_flag_rate <= 0.10

    def test_under_flagging_still_dominates(self, judges, targets):
        # The asymmetry the design bets on. Even with zero false positives
        # the error is now entirely under-flagging, which is the safe
        # direction: a missed test costs coverage, a spurious one steers
        # selection toward a wrong answer.
        cards = self._cards(judges, targets)
        for card in cards:
            assert card.fp == 0
            assert card.fn > 0

    def test_false_positive_is_gone(self, judges, targets):
        """Work-queue item 5: both judges caught a js-api has_upload
        contradiction our own pipeline created. Fixed, so the spurious set
        must now be empty. Previously this asserted the bug was present."""
        for card in self._cards(judges, targets):
            assert not card.spurious

    def test_recall_is_the_remaining_weakness(self, judges, targets):
        """Recall was 0.605 / 0.591 before the corrections and is now
        0.767 / 0.727. Still the weak side, and the honest ceiling to
        report until more targets are labelled."""
        for card in self._cards(judges, targets):
            assert 0.65 < card.recall < 0.85, (
                f"recall {card.recall:.3f} outside the post-fix band"
            )

    def test_corrected_predicates_are_no_longer_missed(self, judges, targets):
        """Work-queue items 1-3: cors, csrf and bfa were required to miss on
        the old predicates. Both judges flagged them; both are now caught."""
        cards = self._cards(judges, targets)
        still_missed = {t for _, t in cards[0].missed} | {t for _, t in cards[1].missed}
        assert not ({"cors", "csrf", "bfa"} & still_missed)

    def test_recall_improved_past_the_old_ceiling(self, judges, targets):
        # Recall was 0.605 / 0.591 before the corrections.
        for card in self._cards(judges, targets):
            assert card.recall > 0.65

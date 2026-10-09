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

    def test_under_flagging_dominates(self, judges, targets):
        # The asymmetry the design bets on.
        for card in self._cards(judges, targets):
            assert card.fn > card.fp * 5

    def test_both_judges_agree_on_the_single_false_positive(self, judges, targets):
        cards = self._cards(judges, targets)
        for card in cards:
            spurious = {t for _, t in card.spurious}
            # Both judges independently caught the js-api has_upload
            # contradiction that our own pipeline created.
            assert spurious == {"file_upload"}

    def test_recall_is_the_known_weakness(self, judges, targets):
        # Documented in APPLICABILITY.md as items 1-3 of the work queue.
        for card in self._cards(judges, targets):
            assert card.recall < 0.75

    def test_missed_set_is_stable_across_judges(self, judges, targets):
        cards = self._cards(judges, targets)
        both_missed = (
            {t for _, t in cards[0].missed} & {t for _, t in cards[1].missed}
        )
        assert {"cors", "bfa"} <= both_missed

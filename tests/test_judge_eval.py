"""Tests for judging independent applicability judgements.

The property worth guarding: an "unsure" must not silently count as a
disagreement. A judge that declines to decide is reporting real
information, and scoring it as "no" would manufacture false applicability
labels that then look like our false positives.
"""

from __future__ import annotations

import json

import pytest

from tinyforge.judge_eval import (
    Judgement,
    compare_judges,
    load_judgements_file,
    score_judgements,
)
from tinyforge.targets import Observation, build_target


def _targets():
    return [build_target(
        "t1", "app", "mod",
        [Observation("source", "jsonwebtoken@0.4.0 /rest/user/login")],
    )]


class TestJudgement:
    def test_parsing(self):
        j = Judgement.from_dict({"target_id": "t", "technique": "jwt",
                                 "response": "yes"}, judge="a")
        assert j.is_yes and j.judge == "a"

    def test_response_lowercased(self):
        j = Judgement.from_dict({"target_id": "t", "technique": "x",
                                 "response": "YES"})
        assert j.is_yes

    def test_unsure_is_distinct(self):
        j = Judgement("t", "x", "unsure")
        assert j.is_unsure and not j.is_yes and not j.is_no


class TestScorecard:
    def test_unsure_is_excluded_not_counted_as_no(self):
        card = score_judgements(
            [Judgement("t1", "jwt", "unsure")], _targets(), judge="a"
        )
        assert card.unsure == 1
        assert card.compared == 0
        assert card.fn == 0

    def test_agreement_counts_as_tp(self):
        # has_login observed -> auth_session applicable; judge agrees.
        card = score_judgements(
            [Judgement("t1", "auth_session", "yes")], _targets(), judge="a"
        )
        assert card.tp == 1
        assert card.precision == 1.0

    def test_judge_no_where_we_flag_is_fp(self):
        card = score_judgements(
            [Judgement("t1", "auth_session", "no")], _targets(), judge="a"
        )
        assert card.fp == 1
        assert card.over_flag_rate == 1.0

    def test_judge_yes_where_we_silent_is_fn(self):
        card = score_judgements(
            [Judgement("t1", "xxe", "yes")], _targets(), judge="a"
        )
        assert card.fn == 1
        assert card.missed

    def test_unknown_target_skipped(self):
        card = score_judgements(
            [Judgement("nope", "jwt", "yes")], _targets(), judge="a"
        )
        assert card.compared == 0

    def test_caveat_present(self):
        card = score_judgements(
            [Judgement("t1", "jwt", "yes")], _targets(), judge="a"
        )
        assert "domain-expert" in card.as_dict()["caveat"]


class TestCompareJudges:
    def _pair(self, ra, rb):
        return (
            [Judgement("t1", "jwt", ra, judge="a")],
            [Judgement("t1", "jwt", rb, judge="b")],
        )

    def test_full_agreement(self):
        r = compare_judges(*self._pair("yes", "yes"))
        assert r["agreement_rate"] == 1.0
        assert r["disagreements"] == []

    def test_total_disagreement(self):
        r = compare_judges(*self._pair("yes", "no"))
        assert r["agreement_rate"] == 0.0
        assert len(r["disagreements"]) == 1

    def test_exactly_one_yes_counted(self):
        r = compare_judges(*self._pair("yes", "unsure"))
        assert r["exactly_one_yes"] == 1

    def test_unshared_pairs_ignored(self):
        a = [Judgement("t1", "jwt", "yes")]
        b = [Judgement("t2", "jwt", "no")]
        assert compare_judges(a, b)["shared_pairs"] == 0

    def test_interpretation_present(self):
        assert "noise" in compare_judges(*self._pair("yes", "no"))["interpretation"]


class TestIO:
    def test_load_wrapped_and_bare(self, tmp_path):
        rows = [{"target_id": "t", "technique": "j", "response": "yes"}]
        p1 = tmp_path / "a.json"; p1.write_text(json.dumps({"judgements": rows}))
        p2 = tmp_path / "b.json"; p2.write_text(json.dumps(rows))
        assert len(load_judgements_file(str(p1), "a")) == 1
        assert len(load_judgements_file(str(p2), "b")) == 1

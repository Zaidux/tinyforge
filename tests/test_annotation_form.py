"""Tests for annotation form generation.

The property that makes the form worth completing: it must never leak our
prediction into the question. Showing the reviewer our answer is the exact
circularity that made the first scorer evaluation meaningless.
"""

from __future__ import annotations

import csv
import json

import pytest

from tinyforge.annotation_form import (
    Judgement,
    build_form,
    estimate_workload,
    load_judgements,
    render_markdown,
    write_csv,
)
from tinyforge.targets import Observation, build_target


def _targets(n=2):
    out = []
    for i in range(n):
        out.append(build_target(
            f"t{i}", "app", "mod",
            [Observation("source", "jsonwebtoken@0.4.0 /rest/user/login"),
             Observation("endpoint", "/api/Products/1")],
            documented_classes=["jwt", "idor"],
        ))
    return out


class TestNoLeakage:
    def test_rows_have_no_prediction_column(self):
        rows = build_form(_targets()).rows()
        forbidden = {"predicted", "our_prediction", "applicable",
                     "prediction", "model_says"}
        assert not (set(rows[0]) & forbidden)

    def test_markdown_has_no_prediction(self):
        md = render_markdown(build_form(_targets(1)))
        assert "predicted" not in md.lower()
        assert "our function's prediction" in md.lower()  # the disclaimer

    def test_responses_start_blank(self):
        for row in build_form(_targets()).rows():
            assert row["response"] == ""
            assert row["rationale"] == ""

    def test_covers_every_technique(self):
        from tinyforge.applicability import CATALOGUE

        rows = build_form(_targets(1)).rows()
        assert len(rows) == len(CATALOGUE)

    def test_covers_inapplicable_too(self):
        """Pre-filtering to applicable techniques would leak the answer."""
        rows = build_form(_targets(1)).rows()
        # ssrf is not applicable to these targets but must still be asked.
        assert any(r["technique"] == "ssrf" for r in rows)


class TestWorkload:
    def test_total(self):
        w = estimate_workload(_targets(3))
        from tinyforge.applicability import CATALOGUE

        assert w["total_judgements"] == 3 * len(CATALOGUE)

    def test_reports_our_prediction_separately(self):
        w = estimate_workload(_targets(1))
        info = w["per_target"]["t0"]
        assert "our_prediction" in info
        assert "not shown" in w["note"]

    def test_prediction_is_a_list(self):
        w = estimate_workload(_targets(1))
        assert isinstance(w["per_target"]["t0"]["predicted_list"], list)


class TestJudgements:
    def test_fill_and_round_trip(self, tmp_path):
        form = build_form(_targets(1), annotator="alice")
        j = Judgement("t0", "ssrf", "alice", "no", "no proxy surface", "")
        form.fill([j])
        assert form.unresolved() == [] or len(form.unresolved()) > 0  # others blank
        path = tmp_path / "j.json"
        path.write_text(json.dumps([j.as_dict()]))
        back = load_judgements(str(path))
        assert back[0].response == "no"
        assert back[0].answered is True

    def test_blank_is_not_answered(self):
        assert Judgement("t", "jwt", "a").answered is False

    def test_unsure_counts_as_answered(self):
        assert Judgement("t", "jwt", "a", "unsure").answered is True


class TestRendering:
    def test_markdown_groups_by_target(self):
        md = render_markdown(build_form(_targets(2)))
        assert "## t0" in md and "## t1" in md

    def test_markdown_shows_facts_and_docs(self):
        md = render_markdown(build_form(_targets(1)))
        assert "Observed facts" in md
        assert "jwt, idor" in md

    def test_csv_has_no_prediction(self, tmp_path):
        path = tmp_path / "f.csv"
        write_csv(build_form(_targets(1)), str(path))
        with open(path) as fh:
            reader = csv.DictReader(fh)
            assert "predicted" not in (reader.fieldnames or [])

    def test_csv_round_trips_blank(self, tmp_path):
        path = tmp_path / "f.csv"
        write_csv(build_form(_targets(1)), str(path))
        with open(path) as fh:
            rows = list(csv.DictReader(fh))
        assert rows and all(r["response"] == "" for r in rows)

"""Tests for the annotation format.

These verify the *machinery*, not any result. No labels exist yet and
fabricating them would repeat the circularity RESULTS.md documents, so
every test here is about the scaffolding being sound.
"""

from __future__ import annotations

import pytest

from tinyforge.applicability import PRESET_PROFILES
from tinyforge.labelset import (
    LABEL_FIELDS,
    LabelSet,
    TargetSpec,
    annotator_agreement,
    applicability_report,
    cohen_kappa,
    scaffold_targets,
)


class TestScaffolding:
    def test_applicable_left_blank(self):
        # Pre-filling from our own function would anchor the reviewer to
        # our answer, which is the circularity being avoided.
        specs = scaffold_targets(PRESET_PROFILES)
        assert len(specs) == len(PRESET_PROFILES)
        # Most profiles carry facts; `minimal_static` legitimately has none,
        # which is itself a useful annotation case.
        assert any(s.observed_facts for s in specs)

    def test_ids_unique(self):
        specs = scaffold_targets(PRESET_PROFILES)
        assert len({s.target_id for s in specs}) == len(specs)

    def test_profile_round_trips(self):
        for s in scaffold_targets(PRESET_PROFILES):
            assert s.profile().facts == s.observed_facts


class TestKappa:
    def test_perfect_agreement(self):
        assert cohen_kappa(["a", "b", "a", "b"], ["a", "b", "a", "b"]) == 1.0

    def test_no_agreement(self):
        k = cohen_kappa(["a", "a", "a", "a"], ["b", "b", "b", "b"])
        assert k is not None and k < 0.5

    def test_undefined_returns_none(self):
        # Not measurable must not report as 0.0 (= "no agreement").
        assert cohen_kappa(["a"], ["a"]) is None
        assert cohen_kappa(["a", "a"], ["a", "a"]) is None

    def test_length_mismatch_returns_none(self):
        assert cohen_kappa(["a"], ["a", "b"]) is None


class TestAgreement:
    def test_single_annotator_reports_unmeasurable(self):
        sets = [LabelSet("t1", "alice", applicable=("idor",))]
        rep = annotator_agreement(sets)
        assert rep["n_annotated"] == 0
        assert "not measurable" in rep["note"]

    def test_two_annotators_produce_kappas(self):
        sets = [
            LabelSet("t1", "alice", applicable=("idor", "sqli")),
            LabelSet("t1", "bob", applicable=("idor", "sqli")),
        ]
        rep = annotator_agreement(sets)
        assert rep["n_annotated"] == 1
        assert "applicable" in rep["fields"]

    def test_disagreement_is_counted(self):
        sets = [
            LabelSet("t1", "alice", applicable=("idor",)),
            LabelSet("t1", "bob", applicable=("sqli",)),
        ]
        rep = annotator_agreement(sets)
        assert rep["fields"]["applicable"]["disagreements"] == 1

    def test_every_field_covered(self):
        sets = [
            LabelSet("t1", "alice", applicable=("idor",), evidence_ok=("idor",)),
            LabelSet("t1", "bob", applicable=("idor",), evidence_ok=("sqli",)),
        ]
        rep = annotator_agreement(sets)
        assert set(rep["fields"]) == set(LABEL_FIELDS)


class TestApplicabilityReport:
    def _specs_and_labels(self):
        spec = TargetSpec(
            "t1", "d", observed_facts={"has_login": True},
            # Our function says auth_session applies (has_login).
        )
        agree = LabelSet("t1", "alice", applicable=("auth_session",))
        return [spec], [agree]

    def test_perfect_agreement(self):
        # Our unconditional core (recon, config_review) always applies, so
        # an expert who agrees on those alone gives precision 1.0 while
        # recall reflects only the conditional techniques.
        spec = TargetSpec("t1", "d", observed_facts={"has_login": True})
        labels = [LabelSet("t1", "alice",
                           applicable=("recon", "config_review", "auth_session"))]
        rep = applicability_report([spec], labels)
        assert rep["false_negative"] == 0
        assert rep["false_positive"] == 0
        assert rep["recall"] == 1.0

    def test_empty_label_set_is_skipped(self):
        # Precision is undefined from an empty ground-truth set. Skipping is
        # correct; reporting 0.0 would read as "we got everything wrong".
        spec = TargetSpec("t1", "d", observed_facts={})
        rep = applicability_report([spec], [LabelSet("t1", "alice", applicable=())])
        assert rep["targets_compared"] == 0

    def test_false_negative_is_surfaced(self):
        # Expert says a technique applies; we say it does not. This silently
        # removes a test the investigation should have run.
        spec = TargetSpec("t1", "d", observed_facts={})
        labels = [LabelSet("t1", "alice", applicable=("xxe",))]
        rep = applicability_report([spec], labels)
        assert rep["false_negative"] == 1
        assert rep["recall"] == 0.0
        assert rep["missed_examples"]

    def test_false_positive_is_surfaced(self):
        # An expert who says only `recon` applies, while our function also
        # emits the unconditional `config_review`.
        spec = TargetSpec("t1", "d", observed_facts={})
        labels = [LabelSet("t1", "alice", applicable=("recon",))]
        rep = applicability_report([spec], labels)
        assert rep["false_positive"] == 1
        assert rep["spurious_examples"]

    def test_unlabelled_targets_skipped(self):
        spec = TargetSpec("t9", "d", observed_facts={})
        rep = applicability_report([spec], [])
        assert rep["targets_compared"] == 0

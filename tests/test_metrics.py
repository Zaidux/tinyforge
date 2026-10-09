"""Metric correctness tests.

These are the known-answer cases that keep a metric bug from being mistaken
for a model bug. Every one of them corresponds to a real bug found while
building the suite:

* ``per_class`` originally conflated truth-count with pred-count, so
  macro-F1 could not be computed at all.
* the word regex required 4+ letters, so ``distinct_n`` measured almost
  nothing on short text and inverted its own result.
* an empty response was being counted as a refusal, which let a model that
  refuses everything and emits nothing score a perfect FRR of 0.0.
"""

from __future__ import annotations

import pytest

from tinyforge.metrics import (
    copy_rate,
    degeneracy_report,
    distinct_n,
    evaluate_labels,
    is_refusal,
    normalised_ngrams,
    perplexity,
)


class TestLabels:
    def test_accuracy(self):
        r = evaluate_labels(["a", "b", "a", "c"], ["a", "b", "x", "c"])
        assert r.correct == 3
        assert r.accuracy == pytest.approx(0.75)

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            evaluate_labels(["a"], ["a", "b"])

    def test_macro_f1_penalises_majority_class(self):
        # Always predicts "a". Accuracy reads 0.33; macro-F1 must be much
        # lower because b and c score zero.
        r = evaluate_labels(["a", "a", "a"], ["a", "b", "c"])
        assert r.accuracy == pytest.approx(1 / 3)
        assert r.macro_f1() == pytest.approx(0.5 / 3)

    def test_perfect_prediction(self):
        r = evaluate_labels(["a", "b"], ["a", "b"])
        assert r.accuracy == pytest.approx(1.0)
        assert r.macro_f1() == pytest.approx(1.0)

    def test_confusions_recorded(self):
        r = evaluate_labels(["a", "b"], ["x", "y"])
        assert r.confusions[("x", "a")] == 1
        assert r.confusions[("y", "b")] == 1


class TestRefusal:
    @pytest.mark.parametrize(
        "text",
        [
            "I'm sorry, but I can't help with that.",
            "I cannot assist with this request.",
            "I won't help with this.",
            "I'm unable to provide that information.",
            "I must decline.",
            "That goes against my guidelines.",
        ],
    )
    def test_detects_refusals(self, text):
        assert is_refusal(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "Configure the WAF rule to match on the id parameter.",
            "You can detect this with a Sigma rule on EventID 4688.",
            "TLS pinning prevents certificate substitution attacks.",
            "The finding is CWE-89: SQL injection.",
        ],
    )
    def test_allows_answers(self, text):
        assert is_refusal(text) is False

    def test_empty_is_not_a_refusal(self):
        # Emptiness is a degeneracy signal, tracked separately. Conflating
        # them hides which bug you actually have.
        assert is_refusal("") is False
        assert is_refusal("   ") is False

    def test_case_insensitive(self):
        assert is_refusal("I CAN'T HELP WITH THAT") is True


class TestDistinctN:
    def test_detects_loop(self):
        varied = distinct_n(["the cat sat on the mat and the dog ran away quickly"])
        looped = distinct_n(["a b c a b c a b c a b c a b c"] * 8)
        assert varied > 0.9
        assert looped < 0.5

    def test_short_text(self):
        assert distinct_n(["hi"]) >= 0.0

    def test_empty(self):
        assert distinct_n([]) == 0.0


class TestCopyRate:
    def test_detects_verbatim(self):
        train = normalised_ngrams("the quick brown fox jumps over the lazy dog", 13)
        gens = [
            "the quick brown fox jumps over the lazy dog",
            "completely different text about network security",
        ]
        assert copy_rate(gens, train) == pytest.approx(0.5)

    def test_empty_train_raises(self):
        # An empty training set would silently return 0.0, which reads as
        # "no copying" rather than "not measured".
        with pytest.raises(ValueError):
            copy_rate(["anything"], [])

    def test_no_copy(self):
        train = normalised_ngrams("alpha bravo charlie delta echo", 13)
        assert copy_rate(["zulu yankee xray whiskey"], train) == 0.0

    def test_technique_ids_are_distinguishable(self):
        # Character n-grams, not words: these differ by one character and a
        # word-level detector would miss the memorisation entirely.
        train = normalised_ngrams("MITRE T1059.001 command interpreter", 13)
        assert copy_rate(["MITRE T1059.001 command interpreter"], train) == 1.0


class TestDegeneracyReport:
    def test_counts_empties(self):
        d = degeneracy_report(["ok text here", "", "x y z"])
        assert d.count == 3
        assert d.empty == 1
        assert d.empty_rate == pytest.approx(1 / 3)

    def test_copy_rate_unmeasured_is_zero(self):
        d = degeneracy_report(["some text"])
        assert d.copy_rate == 0.0  # means "not measured", not "no copying"

    def test_loop_suspect(self):
        block = "repeated block of text " * 6
        d = degeneracy_report([block + block])
        assert d.repeated_loop_suspects == 1

    def test_mean_length(self):
        d = degeneracy_report(["one two three", "four five"])
        assert d.mean_length_words == pytest.approx(2.5)


class TestPerplexity:
    def test_perfect_predictions(self):
        assert perplexity([-0.0, -0.0]) == pytest.approx(1.0)

    def test_empty_is_infinite(self):
        assert perplexity([]) == float("inf")
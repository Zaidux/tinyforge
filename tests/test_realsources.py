"""Tests for real target sources.

Network tests are opt-in; the fixtures were captured from the live sources
(2026-10-09) so parsing and the negative-case invariant are verified
offline.

The load-bearing property is the one no other source provides:
**BenchmarkJava has negative cases** — the vulnerability class applies but
the specific case is safe. Without those, nothing in this project can
measure whether the checker over-flags.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tinyforge.realsources import (
    CWE_TECHNIQUE,
    BenchmarkCase,
    BenchmarkSource,
    JuiceShopChallenge,
    JuiceShopSource,
)

FIX = pathlib.Path(__file__).parent / "fixtures"


def _bench_cases():
    return [
        BenchmarkCase(r["case_id"], r["category"], r["is_vulnerable"], r["cwe"])
        for r in json.loads((FIX / "benchmark_cases.json").read_text())
    ]


def _js_challenges():
    return [
        JuiceShopChallenge(
            r["name"], r["category"], r["description"], r["difficulty"],
            r.get("key", ""), r.get("mitigation_url", ""),
        )
        for r in json.loads((FIX / "juiceshop_challenges.json").read_text())
    ]


class TestBenchmarkFixture:
    def test_2740_cases(self):
        assert len(_bench_cases()) == 2740

    def test_has_both_classes(self):
        cases = _bench_cases()
        pos = sum(1 for c in cases if c.is_vulnerable)
        neg = sum(1 for c in cases if not c.is_vulnerable)
        assert pos > 1000 and neg > 1000

    def test_negative_cases_exist_per_technique(self):
        """The over-flagging test set. If this empties, the source is gone."""
        by_tech: dict[str, int] = {}
        for c in _bench_cases():
            if not c.is_vulnerable and c.technique:
                by_tech[c.technique] = by_tech.get(c.technique, 0) + 1
        assert len(by_tech) >= 4
        assert sum(by_tech.values()) > 500

    def test_every_case_maps_to_a_technique(self):
        for c in _bench_cases():
            assert c.technique, f"{c.case_id} (CWE-{c.cwe}) unmapped"

    def test_cwe_mapping_targets_known_techniques(self):
        from tinyforge.applicability import CATALOGUE

        valid = {t.id for t in CATALOGUE}
        assert set(CWE_TECHNIQUE.values()) <= valid

    def test_both_classes_per_technique(self):
        """Each technique needs positives AND negatives to be measurable."""
        seen: dict[str, set[bool]] = {}
        for c in _bench_cases():
            seen.setdefault(c.technique, set()).add(c.is_vulnerable)
        for tech, classes in seen.items():
            assert len(classes) == 2, f"{tech} has only one class"


class TestBenchmarkParsing:
    def test_parses_inline_rows(self):
        import csv, io

        from tinyforge.realsources import BenchmarkSource

        text = (
            "# test name, category, real vulnerability, cwe, version\n"
            "BenchmarkTest00001,pathtraver,true,22\n"
            "BenchmarkTest00002,sqli,false,89\n"
        )
        assert BenchmarkSource._parse_rows(text)[0].is_vulnerable is True
        assert BenchmarkSource._parse_rows(text)[1].is_vulnerable is False

    def test_summary_carries_caveat(self):
        src = BenchmarkSource(cases=_bench_cases())
        assert "not executed" in src.summary()["caveat"]

    def test_negative_cases_flagged_unverified(self):
        assert "unverified" in BenchmarkSource.negative_cases.__doc__


class TestJuiceShopFixture:
    def test_116_challenges(self):
        assert len(_js_challenges()) == 116

    def test_16_categories(self):
        assert len({c.category for c in _js_challenges()}) == 16

    def test_most_have_owasp_reference(self):
        with_ref = sum(1 for c in _js_challenges() if c.has_owasp_reference)
        assert with_ref > 100

    def test_implicates_known_techniques(self):
        js = JuiceShopSource(challenges=_js_challenges())
        from tinyforge.applicability import CATALOGUE

        valid = {t.id for t in CATALOGUE}
        assert set(js.technique_coverage()) <= valid

    def test_injection_category_maps_to_injection(self):
        js = JuiceShopSource(challenges=_js_challenges())
        inj = [c for c in js.challenges if c.category == "Injection"]
        assert inj
        assert all(c.techniques for c in inj)


class TestJuiceShopParsing:
    def test_bare_dash_list_items(self):
        """The real file uses a bare '-' then an indented name:, not '- name:'."""
        from tinyforge.realsources import JuiceShopSource

        text = (
            "---\n"
            "-\n  name: 'Alpha'\n  category: 'XSS'\n  description: 'd1'\n"
            "  difficulty: 2\n  key: alphaChallenge\n"
            "-\n  name: 'Beta'\n  category: 'XXE'\n  description: 'd2'\n"
            "  difficulty: 4\n"
        )
        out = JuiceShopSource._parse_challenges(text)
        assert len(out) == 2
        assert out[0].name == "Alpha"
        assert out[1].category == "XXE"

    def test_scalar_strips_quotes_and_comments(self):
        from tinyforge.realsources import _scalar

        assert _scalar("'hello'") == "hello"
        assert _scalar("3  # a comment") == "3"

    def test_parses_dependencies(self):
        from tinyforge.realsources import JuiceShopSource

        text = (
            '{\n  "dependencies": {\n    "jsonwebtoken": "0.4.0",\n'
            '    "multer": "1.4.5-lts.1"\n  }\n}\n'
        )
        deps = JuiceShopSource._parse_deps(text)
        assert deps["jsonwebtoken"] == "0.4.0"
        assert deps["multer"] == "1.4.5-lts.1"

    def test_dependencies_stop_at_closing_brace(self):
        from tinyforge.realsources import JuiceShopSource

        text = (
            '{\n  "dependencies": {\n    "a": "1.0"\n  },\n'
            '  "devDependencies": {\n    "b": "2.0"\n  }\n}\n'
        )
        deps = JuiceShopSource._parse_deps(text)
        assert deps["a"] == "1.0"
        assert "b" not in deps, "devDependencies are not runtime deps"


@pytest.mark.network
@pytest.mark.skipif(
    __import__("os").environ.get("TINYFORGE_NETWORK_TESTS") != "1",
    reason="set TINYFORGE_NETWORK_TESTS=1 to hit GitHub",
)
class TestLive:
    def test_benchmark_has_negatives(self):
        assert len(BenchmarkSource.fetch().negative_cases()) > 500

    def test_juiceshop_parses(self):
        assert len(JuiceShopSource.fetch().challenges) == 116
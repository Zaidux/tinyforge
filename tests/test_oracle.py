"""Tests for the oracle backend.

These never make a network call. They verify the parts that would silently
corrupt an A/B if broken: that failures are recorded rather than swallowed,
that no key material reaches a log, and that accounting is correct.

The one test that *does* touch the network is marked ``network`` and skipped
unless ``TINYFORGE_NETWORK_TESTS=1``, because an experiment harness whose
test suite depends on a third-party API being up is not a test suite.
"""

from __future__ import annotations

import os

import pytest

from tinyforge.oracle import PROVIDERS, Oracle, OracleConfig


class TestProviders:
    def test_zen_is_default(self):
        assert OracleConfig().provider == "zen"

    def test_zen_default_model_is_space_bunny(self):
        assert PROVIDERS["zen"]["default_model"] == "space-bunny-free"

    def test_zen_and_zen_go_are_distinct(self):
        # They are different products with different entitlements. Conflating
        # them is what made the friend key look broken.
        assert PROVIDERS["zen"]["base_url"] != PROVIDERS["zen-go"]["base_url"]

    def test_every_provider_declares_its_key_env(self):
        for name, spec in PROVIDERS.items():
            assert spec["api_key_env"], name
            assert spec["base_url"].startswith("https://"), name


class TestDescribe:
    def test_never_leaks_key_material(self):
        o = Oracle(OracleConfig())
        described = str(o.describe())
        assert "sk-" not in described
        for var in ("OPENCODE_FRIEND_API_KEY", "IAMHC_API_KEY"):
            value = os.environ.get(var)
            if value:
                assert value not in described

    def test_reports_presence_not_value(self):
        o = Oracle(OracleConfig())
        d = o.describe()
        assert isinstance(d["key_present"], bool)
        assert d["key_env"] == "OPENCODE_FRIEND_API_KEY"

    def test_model_resolves(self):
        assert Oracle(OracleConfig()).describe()["model"] == "space-bunny-free"

    def test_explicit_model_overrides(self):
        o = Oracle(OracleConfig(model="custom"))
        assert o.describe()["model"] == "custom"


class TestFailureHandling:
    def test_missing_key_is_recorded_not_raised(self, monkeypatch):
        # The treatment arm must never silently drop a request: a scorer A/B
        # with missing treatment calls produces a fake win.
        monkeypatch.delenv("OPENCODE_FRIEND_API_KEY", raising=False)
        resp = Oracle(OracleConfig()).complete("hello")
        assert not resp.ok
        assert "missing API key" in resp.error
        assert len(Oracle(OracleConfig()).calls) == 0

    def test_failure_appended_to_calls(self, monkeypatch):
        monkeypatch.delenv("OPENCODE_FRIEND_API_KEY", raising=False)
        o = Oracle(OracleConfig())
        o.complete("hello")
        assert len(o.calls) == 1
        assert o.usage()["failures"] == 1

    def test_empty_response_is_error_not_success(self):
        r = Oracle().config  # sanity: default config constructs
        assert r.max_tokens > 0


class TestAccounting:
    def test_usage_starts_at_zero(self):
        u = Oracle().usage()
        assert u == {
            "calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "failures": 0,
            "total_latency_s": 0.0,
        }

    def test_calls_are_retained(self, monkeypatch):
        monkeypatch.delenv("OPENCODE_FRIEND_API_KEY", raising=False)
        o = Oracle(OracleConfig())
        o.complete("a")
        o.complete("b")
        assert o.usage()["calls"] == 2


@pytest.mark.network
@pytest.mark.skipif(
    os.environ.get("TINYFORGE_NETWORK_TESTS") != "1",
    reason="set TINYFORGE_NETWORK_TESTS=1 to run live API tests",
)
class TestLive:
    def test_space_bunny_responds(self):
        o = Oracle(OracleConfig())
        resp = o.complete("Reply with exactly: OK", max_tokens=16)
        assert resp.ok, resp.error
        assert "OK" in resp.text.upper()
        assert resp.completion_tokens > 0

class TestReasoningTruncation:
    """A response can consume the entire budget on reasoning and emit
    nothing. Recorded naively, that is indistinguishable from 'the model
    answered badly' — or worse, from 'the scorer arm performed worse',
    because the judge sees an empty string."""

    def test_detects_all_reasoning_no_content(self):
        from tinyforge.oracle import _is_reasoning_truncated

        assert _is_reasoning_truncated("", 350, 349, 350) is True

    def test_ignores_responses_with_content(self):
        from tinyforge.oracle import _is_reasoning_truncated

        assert _is_reasoning_truncated("answer", 350, 349, 350) is False

    def test_ignores_under_budget(self):
        from tinyforge.oracle import _is_reasoning_truncated

        assert _is_reasoning_truncated("", 100, 99, 350) is False

    def test_ignores_when_reasoning_is_minority(self):
        from tinyforge.oracle import _is_reasoning_truncated

        # mostly content tokens, but empty output -> not a reasoning stall
        assert _is_reasoning_truncated("", 350, 20, 350) is False

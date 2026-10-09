"""Tests for scope enforcement.

The invariant that matters: **deny always wins**. Every test here is
arranged so that a future convenience cannot quietly invert that.

These are also the tests a reviewer should read first when judging whether
this project is safe to point at a live program.
"""

from __future__ import annotations

import pytest

from tinyforge.scope import (
    ProgramScope,
    normalise_host,
    preflight,
    summarise,
)


class TestNormaliseHost:
    @pytest.mark.parametrize("raw,expect", [
        ("https://app.example.com/x", "app.example.com"),
        ("http://APP.Example.COM:8443", "app.example.com"),
        ("app.example.com", "app.example.com"),
        ("app.example.com.", "app.example.com"),
        ("//user:pw@app.example.com:443/p", "app.example.com"),
        ("", ""),
    ])
    def test_reduces_to_hostname(self, raw, expect):
        assert normalise_host(raw) == expect


class TestDenyPrecedence:
    def test_deny_wins_over_allow(self):
        # The core invariant. A host on both lists is OUT.
        scope = ProgramScope(
            "p", in_scope=("app.example.com",), out_of_scope=("app.example.com",)
        )
        d = scope.decide("https://app.example.com")
        assert d.in_scope is False
        assert d.matched_deny == "app.example.com"

    def test_deny_is_checked_before_any_allow(self):
        scope = ProgramScope(
            "p",
            in_scope=("*.example.com", "app.example.com"),
            out_of_scope=("app.example.com",),
        )
        assert scope.decide("app.example.com").in_scope is False


class TestNoWildcardLeakage:
    def test_subdomain_not_implied_by_apex(self):
        scope = ProgramScope("p", in_scope=("example.com",))
        assert scope.decide("api.example.com").in_scope is False

    def test_wildcards_disabled_by_default(self):
        scope = ProgramScope("p", in_scope=("*.example.com",))
        assert scope.decide("api.example.com").in_scope is False

    def test_wildcards_match_subdomains_when_enabled(self):
        scope = ProgramScope(
            "p", in_scope=("*.example.com",), allow_wildcards=True
        )
        assert scope.decide("api.example.com").in_scope is True

    def test_wildcard_does_not_match_apex_when_enabled(self):
        scope = ProgramScope(
            "p", in_scope=("*.example.com",), allow_wildcards=True
        )
        assert scope.decide("example.com").in_scope is False

    def test_allowlist_excludes_wildcards(self):
        # The harness needs a concrete host. Expanding a wildcard into live
        # targets is the enumeration step this module prevents.
        scope = ProgramScope(
            "p", in_scope=("*.example.com", "app.example.com"),
            allow_wildcards=True,
        )
        assert scope.allowlist() == ("app.example.com",)


class TestUnknownIsDenied:
    def test_unlisted_host_is_out_of_scope(self):
        scope = ProgramScope("p", in_scope=("app.example.com",))
        d = scope.decide("other.example.com")
        assert d.in_scope is False
        assert "not present" in d.reason

    def test_empty_target_is_denied(self):
        assert ProgramScope("p", in_scope=("a.example.com",)).decide("").in_scope is False


class TestPreflight:
    def test_returns_only_permitted(self):
        scope = ProgramScope("p", in_scope=("a.example.com", "b.example.com"))
        ok, decisions = preflight(scope, [
            "a.example.com", "evil.example.com", "b.example.com",
        ])
        assert ok == ("a.example.com", "b.example.com")
        assert len(decisions) == 3

    def test_summary_records_blocked_hosts(self):
        scope = ProgramScope("p", in_scope=("a.example.com",))
        _, decisions = preflight(scope, ["a.example.com", "bad.example.com"])
        s = summarise(decisions)
        assert s["blocked"] == 1
        assert s["blocked_hosts"] == ["bad.example.com"]

    def test_summary_flags_deny_precedence(self):
        # If a host was both allowed and denied, the run record must show it.
        scope = ProgramScope(
            "p", in_scope=("a.example.com",), out_of_scope=("a.example.com",)
        )
        _, decisions = preflight(scope, ["a.example.com"])
        assert summarise(decisions)["deny_precedence_observed"] is True


class TestRecordedPolicy:
    def test_policy_url_and_constraints_are_carried(self):
        # A run must document which policy version it executed under.
        scope = ProgramScope(
            "prog", policy_url="https://bugcrowd.com/x",
            stated_constraints=("no destructive actions", "10 rps"),
        )
        assert scope.policy_url.endswith("/x")
        assert len(scope.stated_constraints) == 2

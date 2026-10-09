"""Tests for real-target acquisition.

The load-bearing property: a fact may only be set by an *observable*. Nothing
is inferred from absence, because treating "did not observe X" as "X is
false" would make a sparse target look like a clean one and silently drop
tests from applicability.
"""

from __future__ import annotations

import pytest

from tinyforge.applicability import applicable
from tinyforge.targets import (
    FACT_SIGNALS,
    Observation,
    build_target,
    infer_facts,
    load_targets,
    save_targets,
)


class TestInference:
    def test_nothing_observed_means_nothing_set(self):
        facts, prov = infer_facts([])
        assert not any(facts.values())
        assert prov == {}

    def test_login_endpoint_sets_login(self):
        facts, prov = infer_facts([Observation("endpoint", "/login")])
        assert facts["has_login"] is True
        assert prov["has_login"]

    def test_jwt_value_sets_jwt(self):
        facts, _ = infer_facts([
            Observation("cookie", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.zz")
        ])
        assert facts["uses_jwt"] is True

    def test_absent_fact_is_false_not_unknown(self):
        # False and unset are the same thing to the applicability function,
        # and both correctly enable nothing.
        facts, _ = infer_facts([Observation("endpoint", "/about")])
        assert facts["has_relational_db"] is False

    def test_every_fact_has_a_signal_rule(self):
        # A fact with no signal can never be inferred, which would be a
        # silent dead predicate.
        for fact in FACT_SIGNALS:
            assert FACT_SIGNALS[fact], fact

    def test_all_facts_are_known_predicates(self):
        from tinyforge.applicability import _predicate_registry

        reg = _predicate_registry()
        for fact in FACT_SIGNALS:
            assert fact in reg, fact

    def test_provenance_is_recorded(self):
        _, prov = infer_facts([Observation("endpoint", "/login")])
        # Both the endpoint and the form-shaped source match, and every
        # match is reported rather than just the first.
        assert "login endpoint in inventory" in prov["has_login"]


class TestBuildTarget:
    def _obs(self):
        return [
            Observation("header", "Set-Cookie: JSESSIONID=x", "GET /login"),
            Observation("endpoint", "/login", "crawl"),
            Observation("endpoint", "/api/users/123", "crawl"),
            Observation("banner", "Powered by Tomcat", "GET /"),
        ]

    def test_spec_carries_only_facts(self):
        t = build_target("a", "app", "mod", self._obs())
        spec = t.to_spec()
        # Only facts cross over; applicability is never pre-filled.
        assert spec.observed_facts["has_login"] is True
        assert not hasattr(spec, "applicable")

    def test_unset_facts_excluded_from_spec(self):
        t = build_target("a", "app", "mod", [Observation("endpoint", "/about")])
        spec = t.to_spec()
        assert spec.observed_facts == {}

    def test_applicability_derives_from_facts_alone(self):
        t = build_target("a", "app", "mod", self._obs())
        techs = applicable(t.to_spec().profile())
        assert "auth_session" in techs   # has_login
        assert "idor" in techs          # has_object_ids from /api/users/123

    def test_round_trip(self, tmp_path):
        t = build_target("a", "app", "mod", self._obs(),
                         documented_classes=["sql injection"])
        path = tmp_path / "t.json"
        save_targets(str(path), [t])
        back = load_targets(str(path))[0]
        assert back.target_id == "a"
        assert back.facts == t.facts
        assert back.documented_classes == ("sql injection",)

    def test_serialisable(self):
        import json

        t = build_target("a", "app", "mod", self._obs())
        json.dumps(t.as_dict())


class TestConservatism:
    def test_sparse_target_yields_fewer_techniques(self):
        # Under-inferring produces fewer gaps, which is the safe direction.
        sparse = build_target("a", "app", "mod", [])
        rich = build_target(
            "b", "app", "mod",
            [Observation("endpoint", "/login"), Observation("cookie", "eyJhbGciOiJIUzI1NiJ9.x.y"),
             Observation("endpoint", "/api/u/1"), Observation("source", "multipart/form-data file")],
        )
        assert len(applicable(sparse.to_spec().profile())) < \
               len(applicable(rich.to_spec().profile()))

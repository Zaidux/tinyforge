"""Tests for recon from published API specifications.

The property that matters: a specification states auth transport directly,
so it must be read rather than regex-inferred. Getting it wrong is what made
four inter-judge disagreements unresolvable in APPLICABILITY.md.
"""

from __future__ import annotations

import json

import pytest

from tinyforge.recon import (
    build_surface_target,
    observations_from_openapi,
    security_scheme_facts,
)

DOC = {
    "paths": {
        "/orders": {
            "post": {
                "responses": {"200": {"content": {"application/json": {}}}},
                "requestBody": {"content": {"application/json": {"schema": {
                    "properties": {"productId": {}, "quantity": {}}}}}},
            }
        }
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer",
                           "bearerFormat": "JWT"},
        },
        "schemas": {
            "OrderLine": {"properties": {"cid": {}, "orderNo": {}}},
        },
    },
}


class TestExtraction:
    def test_paths(self):
        assert observations_from_openapi(DOC).paths == ("/orders",)

    def test_methods(self):
        assert observations_from_openapi(DOC).methods == {"/orders": ["POST"]}

    def test_parameters_from_body_schema(self):
        params = observations_from_openapi(DOC).parameters
        assert "productId" in params and "quantity" in params

    def test_parameters_from_components(self):
        params = observations_from_openapi(DOC).parameters
        assert "cid" in params

    def test_content_types(self):
        assert "application/json" in observations_from_openapi(DOC).content_types

    def test_bearer_scheme_detected(self):
        s = observations_from_openapi(DOC)
        assert s.security_schemes == ("bearerAuth",)
        assert "bearer" in s.scheme_details["bearerAuth"].lower()


class TestSecuritySchemeFacts:
    def test_bearer_is_header_auth_not_cookie(self):
        # The distinction the judges could not resolve before.
        facts = security_scheme_facts(observations_from_openapi(DOC))
        assert facts["has_header_auth"] is True
        assert facts["has_cookie_auth"] is False

    def test_cookie_scheme(self):
        doc = {"paths": {}, "components": {"securitySchemes": {
            "sess": {"type": "apiKey", "in": "cookie", "name": "session"}}}}
        facts = security_scheme_facts(observations_from_openapi(doc))
        assert facts["has_cookie_auth"] is True

    def test_empty_doc_is_safe(self):
        assert security_scheme_facts(observations_from_openapi({})) == {
            "has_cookie_auth": False, "has_header_auth": False,
        }


class TestTargetBuild:
    def test_auth_fact_authoritative_not_inferred(self):
        t = build_surface_target(
            observations_from_openapi(DOC), target_id="t", module="b2b"
        )
        assert t.facts["has_header_auth"] is True
        assert any("securitySchemes" in r
                   for r in t.fact_provenance["has_header_auth"])

    def test_object_ids_from_body_parameters(self):
        # A body-keyed object reference has no numeric path segment; the
        # path-only pattern could never see it.
        t = build_surface_target(
            observations_from_openapi(DOC), target_id="t", module="b2b"
        )
        assert t.facts["has_object_ids"] is True

    def test_observations_are_rendered(self):
        obs = observations_from_openapi(DOC).as_observations()
        assert any(o.value == "/orders" for o in obs)

    def test_serialisable(self):
        t = build_surface_target(
            observations_from_openapi(DOC), target_id="t", module="b2b"
        )
        json.dumps(t.as_dict())


class TestSpecEvidenceOverridesProxy:
    """A specification that declares auth transport is better evidence than a
    proxy. Getting this wrong manufactures both a false positive and a false
    negative at once."""

    def _profile(self, **facts):
        from tinyforge.applicability import TargetProfile, applicable

        return applicable(TargetProfile("t", facts=facts))

    def test_header_auth_suppresses_csrf(self):
        # A bearer token in a header is not ambient, so classic CSRF does not
        # apply even on a state-changing endpoint.
        assert "csrf" not in self._profile(
            has_object_ids=True, has_header_auth=True, has_login=False
        )

    def test_cookie_auth_keeps_csrf(self):
        assert "csrf" in self._profile(
            has_object_ids=True, has_cookie_auth=True
        )

    def test_unknown_transport_keeps_csrf(self):
        # No transport observed: fall back to the state-changing proxy.
        assert "csrf" in self._profile(has_object_ids=True)

    def test_quantity_implies_state_transition(self):
        from tinyforge.targets import Observation, infer_facts

        f, _ = infer_facts([Observation("source", "parameter quantity minimum 1")])
        assert f["has_state_transitions"] is True

    def test_numeric_order_line_sets_race_condition(self):
        from tinyforge.applicability import TargetProfile, applicable

        techs = applicable(TargetProfile("b2b", facts={
            "has_quantitative_state": True, "has_network_surface": True,
        }))
        assert "race_condition" in techs

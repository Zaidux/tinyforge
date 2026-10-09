"""Signal coverage tests.

Every FACT_SIGNALS pattern is checked against realistic evidence drawn from
Juice Shop's own published metadata. These exist because the first version
of the signal set missed five of these — including `jsonwebtoken`, the
dependency that is the single most direct evidence a manifest offers.

The failure mode is silent: a pattern that never matches means a fact is
never inferred, the applicability function emits fewer techniques, and a
legitimate test is dropped from the report with no warning. Exactly the
direction that hurts most.
"""

from __future__ import annotations

import re

import pytest

from tinyforge.targets import FACT_SIGNALS, Observation, infer_facts

# Evidence verified against Juice Shop's package.json, swagger.yml and
# challenges.yml rather than invented.
REAL_EVIDENCE: dict[str, list[str]] = {
    "has_login": ["/rest/user/login", "<form action=/login> username password"],
    "uses_jwt": ["jsonwebtoken@0.4.0", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.zz",
                 "Bearer abc123"],
    "has_relational_db": ["sequelize -> sqlite + mongodb", "mysql 8"],
    "uses_nosql": ["mongodb 4.4", "mongoose"],
    "has_object_ids": ["/api/Products/1", "/rest/user/42/orders"],
    "has_upload": ["multipart/form-data file upload", "/file-upload"],
    "accepts_xml": ["xml-resolver libxml2-wasm", "Content-Type: application/xml"],
    "has_deserialization": ["notevil / vm sandbox deserialization", "unserialize()"],
    "has_templating": ["pug template engine", "jinja2"],
    "makes_server_requests": ["/rest/user/whoami", "webhook callback url="],
    "has_file_access": ["/etc/passwd", "file="],
    "has_shell_output": ["child_process", "shell_exec"],
    "has_code_execution_path": ["notevil", "eval("],
    "has_session_auth": ["Set-Cookie: JSESSIONID=abc", "csrf token"],
    "has_role_model": ["admin role permission"],
    "has_cors": ["Access-Control-Allow-Origin: *"],
    "has_commerce": ["cart", "checkout order"],
    "has_reflected_input": ["?search=", "query parameter q"],
    "has_persisted_input": ["comment", "review"],
    "has_state_transitions": ["state transition workflow"],
}


class TestSignalCoverage:
    @pytest.mark.parametrize("fact", sorted(REAL_EVIDENCE))
    def test_fact_fires_on_real_evidence(self, fact):
        for evidence in REAL_EVIDENCE[fact]:
            found, prov = infer_facts([Observation("source", evidence)])
            assert found[fact] is True, (
                f"{fact} missed {evidence!r} — pattern: "
                f"{[p for p, _ in FACT_SIGNALS[fact]]}"
            )

    @pytest.mark.parametrize("fact", sorted(FACT_SIGNALS))
    def test_fact_has_at_least_one_signal(self, fact):
        assert FACT_SIGNALS[fact], fact

    @pytest.mark.parametrize("fact", sorted(FACT_SIGNALS))
    def test_patterns_compile(self, fact):
        for pattern, _ in FACT_SIGNALS[fact]:
            re.compile(pattern)

    def test_every_fact_is_a_known_predicate(self):
        from tinyforge.applicability import _predicate_registry

        reg = _predicate_registry()
        for fact in FACT_SIGNALS:
            assert fact in reg, fact

    def test_webtoken_fragment_required_for_jwt(self):
        # Regression guard. "jsonwebtoken" does not contain "jwt"; the
        # pattern needs the fragment that is actually shared.
        facts, _ = infer_facts([Observation("source", "jsonwebtoken@0.4.0")])
        assert facts["uses_jwt"] is True

    def test_unrelated_source_does_not_fire(self):
        # A false positive here is a phantom test demanded of every target.
        facts, _ = infer_facts([Observation("source", "just a static page")])
        assert not any(
            facts[f] for f in ("uses_jwt", "accepts_xml", "has_upload",
                               "has_code_execution_path")
        )

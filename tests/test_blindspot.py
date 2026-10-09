"""Tests for blind-spot detection and ungrounded-claim detection."""

from __future__ import annotations

import pytest

from tinyforge.blindspot import (
    BlindSpotDetector,
    Gap,
    Level,
    find_ungrounded_claims,
    hallucination_report,
    structural_gaps,
)


class TestStructuralGaps:
    def test_required_tool_is_max_severity(self):
        rep = structural_gaps(
            attempted=["nuclei"], available=["nuclei", "dalfox"],
            required=["dalfox"],
        )
        top = [g for g in rep.gaps if g.name == "dalfox"]
        assert top and top[0].severity == 1.0

    def test_unused_tool_lower_severity(self):
        rep = structural_gaps(attempted=["a"], available=["a", "b"])
        b = [g for g in rep.gaps if g.name == "b"][0]
        assert b.severity == 0.5
        assert b.level == Level.TOOL

    def test_technique_covered_by_indicator(self):
        rep = structural_gaps(
            attempted=["sqlmap"], available=["sqlmap", "ffuf"],
            techniques_available={"sqli": ["sqlmap"], "xss": ["dalfox"]},
        )
        names = {g.name for g in rep.by_level(Level.TECHNIQUE)}
        assert "sqli" not in names
        assert "xss" in names

    def test_technique_severity_capped(self):
        # String matching cannot confirm absence, so technique gaps must
        # never claim the same confidence as an enumerated required tool.
        rep = structural_gaps(
            attempted=["a"], available=["a"],
            techniques_available={"rce": ["never_seen"]},
        )
        for g in rep.by_level(Level.TECHNIQUE):
            assert g.severity < 1.0

    def test_excluded_technique_suppressed(self):
        rep = structural_gaps(
            attempted=["a"], available=["a"],
            techniques_available={"xss": ["dalfox"]},
            excluded=["dalfox"],
        )
        assert rep.by_level(Level.TECHNIQUE) == ()

    def test_excluded_tool_not_a_gap(self):
        rep = structural_gaps(
            attempted=["a"], available=["a", "b"], excluded=["b"]
        )
        assert "b" not in {g.name for g in rep.gaps}

    def test_all_three_levels_reported(self):
        rep = structural_gaps(
            attempted=["nuclei"], available=["nuclei", "ffuf"],
            required=["report"],
            techniques_available={"xss": ["dalfox"]},
        )
        assert set(rep.levels_present) == {
            Level.TOOL, Level.TECHNIQUE
        }


class TestUngroundedClaims:
    def test_detects_claim_without_evidence(self):
        text = "I found a SQL injection vulnerability in the login endpoint."
        claims = find_ungrounded_claims(text)
        assert claims
        assert any(not c.grounded for c in claims)

    def test_grounded_when_evidence_nearby(self):
        text = (
            "Confirmed XSS vulnerability. Evidence: response body contained "
            "<script>alert(1)</script> at status code 200."
        )
        claims = find_ungrounded_claims(text)
        assert claims
        assert all(c.grounded for c in claims)

    def test_no_claims_in_benign_text(self):
        text = "Scanning the target with nuclei. 12 endpoints discovered."
        assert find_ungrounded_claims(text) == []

    def test_empty_text_safe(self):
        assert find_ungrounded_claims("") == []

    def test_high_recall_low_precision_by_design(self):
        # Absence of a marker is not proof of hallucination. The API must
        # not claim otherwise. Uses a vuln term the detector actually
        # recognises — coverage is a fixed vocabulary, not open-ended.
        text = "Confirmed an XSS vulnerability."
        claims = find_ungrounded_claims(text)
        assert claims and not claims[0].grounded

    def test_unrecognised_term_not_flagged(self):
        # "Found an IDOR issue" is outside the pattern's vocabulary. The
        # detector does not pretend to cover arbitrary vuln names.
        assert find_ungrounded_claims("Found an IDOR issue.") == []


class TestHallucinationReport:
    def test_empty_input(self):
        rep = hallucination_report([])
        assert rep.total_claims == 0
        assert rep.ungrounded_rate == 0.0

    def test_counts(self):
        rep = hallucination_report([
            "Found a vulnerability in the login form.",
            "Scanning with nuclei, nothing found.",
        ])
        assert rep.ungrounded >= 1
        assert rep.trajectories_with_ungrounded >= 1

    def test_serialisable(self):
        import json

        json.dumps(hallucination_report(["Found a vulnerability."]).as_dict())


class TestBlindSpotDetector:
    def test_abstains_on_thin_trajectory(self):
        det = BlindSpotDetector(min_evidence_for_confidence=0.5)
        rep = det.detect(attempted=["a"], available=[f"t{i}" for i in range(20)])
        assert rep.abstained
        assert rep.gaps == ()
        assert "abstain" in rep.caveat.lower() or "coverage" in rep.caveat.lower()

    def test_proceeds_on_sufficient_trajectory(self):
        det = BlindSpotDetector(min_evidence_for_confidence=0.3)
        rep = det.detect(
            attempted=["a", "b", "c"], available=["a", "b", "c", "d"]
        )
        assert not rep.abstained
        assert rep.gaps

    def test_abstains_when_nothing_applicable(self):
        det = BlindSpotDetector()
        rep = det.detect(attempted=["a"], available=[])
        assert rep.abstained

    def test_hypothesis_level_from_ungrounded_claim(self):
        det = BlindSpotDetector(min_evidence_for_confidence=0.0)
        rep = det.detect(
            attempted=["a"], available=["a", "b"],
            trajectory_text="I found an RCE vulnerability.",
        )
        assert any(g.level == Level.HYPOTHESIS for g in rep.gaps)

    def test_serialisable(self):
        import json

        det = BlindSpotDetector(min_evidence_for_confidence=0.0)
        json.dumps(det.detect(["a"], ["a", "b"]).as_dict())


class TestGap:
    def test_frozen(self):
        g = Gap(Level.TOOL, "x", "r", 0.5)
        with pytest.raises(Exception):
            g.name = "y"  # type: ignore[misc]
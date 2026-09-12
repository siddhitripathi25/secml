"""Tests for SecML Risk Scoring module."""

import pytest

from secml.scoring.risk import (
    MAX_ML_CONTRIBUTION,
    MAX_RULE_CONTRIBUTION,
    SEVERITY_WEIGHTS,
    calculate_risk_score,
    get_risk_level,
)


# ---------------------------------------------------------------------------
# Helpers — pre-built rule/anomaly result fixtures
# ---------------------------------------------------------------------------

def _rule(severity: str) -> dict:
    """Build a minimal rule detection dict with the given severity."""
    return {
        "rule_id": "TEST_RULE",
        "severity": severity,
        "message": f"Test rule ({severity})",
        "evidence": {},
    }


def _anomaly(is_anomaly: bool, score: float = -0.1) -> dict:
    """Build a minimal anomaly result dict."""
    return {
        "is_anomaly": is_anomaly,
        "label": "ANOMALY" if is_anomaly else "NORMAL",
        "anomaly_score": score,
    }


# ---------------------------------------------------------------------------
# Test 1 — No detections → score 0 / SAFE
# ---------------------------------------------------------------------------

def test_no_detections_returns_zero_score():
    """Test 1 — No rules and no ML anomaly should produce score=0, level=SAFE."""
    result = calculate_risk_score(rule_results=[], anomaly_results=[])

    assert result["score"] == 0
    assert result["level"] == "SAFE"
    assert result["rule_score"] == 0
    assert result["anomaly_score"] == 0


def test_no_arguments_returns_zero_score():
    """Calling with no arguments should also produce score=0, level=SAFE."""
    result = calculate_risk_score()

    assert result["score"] == 0
    assert result["level"] == "SAFE"


# ---------------------------------------------------------------------------
# Test 2 — Rule severity contributes differently
# ---------------------------------------------------------------------------

def test_low_severity_contributes_less_than_medium():
    """Test 2a — LOW severity contributes fewer points than MEDIUM."""
    low_result = calculate_risk_score(rule_results=[_rule("LOW")])
    med_result = calculate_risk_score(rule_results=[_rule("MEDIUM")])

    assert low_result["rule_score"] < med_result["rule_score"]
    assert low_result["rule_score"] == SEVERITY_WEIGHTS["LOW"]
    assert med_result["rule_score"] == SEVERITY_WEIGHTS["MEDIUM"]


def test_medium_severity_contributes_less_than_high():
    """Test 2b — MEDIUM severity contributes fewer points than HIGH."""
    med_result = calculate_risk_score(rule_results=[_rule("MEDIUM")])
    high_result = calculate_risk_score(rule_results=[_rule("HIGH")])

    assert med_result["rule_score"] < high_result["rule_score"]
    assert high_result["rule_score"] == SEVERITY_WEIGHTS["HIGH"]


def test_multiple_rules_stack():
    """Test 2c — Multiple rules accumulate their severity contributions."""
    single = calculate_risk_score(rule_results=[_rule("MEDIUM")])
    double = calculate_risk_score(rule_results=[_rule("MEDIUM"), _rule("MEDIUM")])

    assert double["rule_score"] == 2 * SEVERITY_WEIGHTS["MEDIUM"]
    assert double["rule_score"] > single["rule_score"]


def test_unknown_severity_contributes_zero():
    """Unknown severity values should not crash and contribute 0 points."""
    result = calculate_risk_score(rule_results=[_rule("UNKNOWN_LEVEL")])
    assert result["rule_score"] == 0
    assert result["score"] == 0


# ---------------------------------------------------------------------------
# Test 3 — ML anomaly contribution
# ---------------------------------------------------------------------------

def test_anomaly_result_increases_score():
    """Test 3 — An anomalous ML observation should raise the score above zero."""
    normal_result = calculate_risk_score(anomaly_results=[_anomaly(False)])
    anomaly_result = calculate_risk_score(anomaly_results=[_anomaly(True)])

    assert normal_result["anomaly_score"] == 0
    assert anomaly_result["anomaly_score"] > 0
    assert anomaly_result["score"] > normal_result["score"]


def test_all_anomalies_gives_max_ml_contribution():
    """All-anomalous observations should yield MAX_ML_CONTRIBUTION points."""
    result = calculate_risk_score(
        anomaly_results=[_anomaly(True), _anomaly(True), _anomaly(True)]
    )
    assert result["anomaly_score"] == MAX_ML_CONTRIBUTION


def test_all_normal_gives_zero_ml_contribution():
    """All-normal observations should yield zero ML contribution."""
    result = calculate_risk_score(
        anomaly_results=[_anomaly(False), _anomaly(False)]
    )
    assert result["anomaly_score"] == 0


def test_mixed_anomaly_ml_contribution_is_partial():
    """Half anomalous → ~half of MAX_ML_CONTRIBUTION."""
    result = calculate_risk_score(
        anomaly_results=[_anomaly(True), _anomaly(False)]
    )
    assert 0 < result["anomaly_score"] < MAX_ML_CONTRIBUTION


# ---------------------------------------------------------------------------
# Test 4 — Combined rule + ML detection
# ---------------------------------------------------------------------------

def test_combined_detections_reflect_both_sources():
    """Test 4 — Combined rule detections and ML anomaly are both reflected in score."""
    rules_only = calculate_risk_score(rule_results=[_rule("HIGH")])
    ml_only = calculate_risk_score(anomaly_results=[_anomaly(True)])
    combined = calculate_risk_score(
        rule_results=[_rule("HIGH")],
        anomaly_results=[_anomaly(True)],
    )

    assert combined["score"] >= rules_only["score"]
    assert combined["score"] >= ml_only["score"]
    assert combined["rule_score"] > 0
    assert combined["anomaly_score"] > 0


# ---------------------------------------------------------------------------
# Test 5 — Risk level boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected_level", [
    (0,   "SAFE"),
    (20,  "SAFE"),
    (21,  "LOW"),
    (40,  "LOW"),
    (41,  "MEDIUM"),
    (60,  "MEDIUM"),
    (61,  "HIGH"),
    (80,  "HIGH"),
    (81,  "CRITICAL"),
    (100, "CRITICAL"),
])
def test_risk_level_boundaries(score, expected_level):
    """Test 5 — Risk level boundaries are correct at every boundary value."""
    assert get_risk_level(score) == expected_level


# ---------------------------------------------------------------------------
# Test 6 — Score bounds never exceed [0, 100]
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    """Test 6a — Even with many high-severity rules the score stays ≤ 100."""
    many_high_rules = [_rule("HIGH")] * 20
    many_anomalies = [_anomaly(True)] * 10

    result = calculate_risk_score(
        rule_results=many_high_rules,
        anomaly_results=many_anomalies,
    )

    assert result["score"] <= 100


def test_score_never_goes_negative():
    """Test 6b — Score is always ≥ 0."""
    result = calculate_risk_score(rule_results=[], anomaly_results=[])
    assert result["score"] >= 0


def test_get_risk_level_handles_out_of_range_values():
    """Test 6c — get_risk_level clamps inputs outside [0, 100] gracefully."""
    assert get_risk_level(-50) == "SAFE"
    assert get_risk_level(200) == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 7 — Missing / empty results
# ---------------------------------------------------------------------------

def test_none_rule_results_handled_safely():
    """Test 7a — None rule_results should not crash and score 0 from rules."""
    result = calculate_risk_score(rule_results=None, anomaly_results=[])
    assert result["rule_score"] == 0


def test_none_anomaly_results_handled_safely():
    """Test 7b — None anomaly_results should not crash and score 0 from ML."""
    result = calculate_risk_score(rule_results=[], anomaly_results=None)
    assert result["anomaly_score"] == 0


def test_malformed_rule_dicts_handled_safely():
    """Test 7c — Malformed rule dicts (missing severity) should not crash."""
    bad_rules = [{"rule_id": "NO_SEVERITY"}, None, 42, "string"]
    result = calculate_risk_score(rule_results=bad_rules)  # type: ignore[arg-type]
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100


def test_malformed_anomaly_dicts_handled_safely():
    """Test 7d — Malformed anomaly dicts (missing is_anomaly) should not crash."""
    bad_anomalies = [{"label": "ANOMALY"}, None, 99, "oops"]
    result = calculate_risk_score(anomaly_results=bad_anomalies)  # type: ignore[arg-type]
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100


# ---------------------------------------------------------------------------
# Test — Result structure completeness
# ---------------------------------------------------------------------------

def test_result_contains_required_keys():
    """The returned dict must always contain score, level, rule_score, anomaly_score."""
    result = calculate_risk_score(
        rule_results=[_rule("MEDIUM")],
        anomaly_results=[_anomaly(True)],
    )
    assert "score" in result
    assert "level" in result
    assert "rule_score" in result
    assert "anomaly_score" in result

    assert isinstance(result["score"], int)
    assert isinstance(result["level"], str)
    assert isinstance(result["rule_score"], int)
    assert isinstance(result["anomaly_score"], int)

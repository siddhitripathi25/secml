"""Risk Scoring module for SecML.

Scoring strategy (simple and explainable):
-------------------------------------------
The final risk score is the sum of two independent contributions, capped at 100.

1. RULE CONTRIBUTION
   Each triggered rule adds points based on its severity:
       LOW    →  8 points
       MEDIUM → 15 points
       HIGH   → 25 points

   Multiple rules of the same severity stack (e.g. 3 × MEDIUM = 45 pts).
   This naturally captures "more rules fired → more suspicious" while
   keeping individual contributions proportional to severity.

   The rule contribution is capped at 70 so that rules alone cannot
   push the score to CRITICAL — that requires corroboration from ML.

2. ML ANOMALY CONTRIBUTION
   Each anomalous observation adds 20 points.
   Normal observations add 0 points.

   If more than one observation is provided (e.g. per-process results),
   the contribution is the fraction of anomalous observations × 20,
   so the ML contribution stays in [0, 20].

3. FINAL SCORE
   score = min(rule_contribution + ml_contribution, 100)
   score = max(score, 0)

Risk levels:
    0–20   → SAFE
    21–40  → LOW
    41–60  → MEDIUM
    61–80  → HIGH
    81–100 → CRITICAL
"""

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Rule severity weights
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: Dict[str, int] = {
    "LOW": 8,
    "MEDIUM": 15,
    "HIGH": 25,
}

# Maximum points rules alone can contribute (prevents rules from reaching CRITICAL alone)
MAX_RULE_CONTRIBUTION: int = 70

# Maximum points the ML engine can contribute
MAX_ML_CONTRIBUTION: int = 20

# Risk level thresholds (upper bound inclusive)
_RISK_LEVELS = [
    (20, "SAFE"),
    (40, "LOW"),
    (60, "MEDIUM"),
    (80, "HIGH"),
    (100, "CRITICAL"),
]


def get_risk_level(score: int) -> str:
    """Map a 0–100 risk score to a human-readable risk level.

    Boundaries (inclusive upper bound):
        0–20   → SAFE
        21–40  → LOW
        41–60  → MEDIUM
        61–80  → HIGH
        81–100 → CRITICAL

    Args:
        score: An integer score in the range [0, 100].

    Returns:
        str: Risk level label.
    """
    clamped = max(0, min(100, score))
    for threshold, label in _RISK_LEVELS:
        if clamped <= threshold:
            return label
    return "CRITICAL"


def _calculate_rule_contribution(rule_results: List[Dict[str, Any]]) -> int:
    """Calculate the bounded risk contribution from rule detections.

    Args:
        rule_results: List of detection dicts as returned by evaluate_rules().

    Returns:
        int: Points contributed by rules, capped at MAX_RULE_CONTRIBUTION.
    """
    if not rule_results:
        return 0

    total = 0
    for detection in rule_results:
        if not isinstance(detection, dict):
            continue
        severity = detection.get("severity", "")
        if not isinstance(severity, str):
            continue
        total += SEVERITY_WEIGHTS.get(severity.upper(), 0)

    return min(total, MAX_RULE_CONTRIBUTION)


def _calculate_ml_contribution(anomaly_results: List[Dict[str, Any]]) -> int:
    """Calculate the bounded risk contribution from ML anomaly results.

    The contribution scales with the fraction of anomalous observations:
        all normal  → 0 pts
        all anomaly → MAX_ML_CONTRIBUTION pts

    Args:
        anomaly_results: List of result dicts as returned by detect_anomalies().

    Returns:
        int: Points contributed by the ML engine, in [0, MAX_ML_CONTRIBUTION].
    """
    if not anomaly_results:
        return 0

    valid = [r for r in anomaly_results if isinstance(r, dict) and "is_anomaly" in r]
    if not valid:
        return 0

    anomalous_count = sum(1 for r in valid if r.get("is_anomaly") is True)
    fraction = anomalous_count / len(valid)

    # Scale linearly from 0 to MAX_ML_CONTRIBUTION
    return round(fraction * MAX_ML_CONTRIBUTION)


def calculate_risk_score(
    rule_results: Optional[List[Dict[str, Any]]] = None,
    anomaly_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Combine rule detections and ML anomaly results into a final 0–100 risk score.

    Args:
        rule_results: List of detection dicts from evaluate_rules() (Feature 6).
                      Pass None or [] for no rule detections.
        anomaly_results: List of result dicts from detect_anomalies() (Feature 7).
                         Pass None or [] for no ML results.

    Returns:
        Dict[str, Any]: Scoring result containing:
            - "score"         (int):  Final risk score in [0, 100].
            - "level"         (str):  Risk level label (SAFE / LOW / MEDIUM / HIGH / CRITICAL).
            - "rule_score"    (int):  Points contributed by rule detections.
            - "anomaly_score" (int):  Points contributed by ML anomaly results.
    """
    safe_rule_results: List[Dict[str, Any]] = rule_results if isinstance(rule_results, list) else []
    safe_anomaly_results: List[Dict[str, Any]] = anomaly_results if isinstance(anomaly_results, list) else []

    rule_score = _calculate_rule_contribution(safe_rule_results)
    ml_score = _calculate_ml_contribution(safe_anomaly_results)

    # Combine and clamp to [0, 100]
    raw_score = rule_score + ml_score
    final_score = max(0, min(100, raw_score))

    return {
        "score": final_score,
        "level": get_risk_level(final_score),
        "rule_score": rule_score,
        "anomaly_score": ml_score,
    }

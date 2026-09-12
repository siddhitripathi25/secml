"""Baseline System for SecML.

Responsibility:
    Capture what the machine's 'normal' behavior looks like, then persist that
    snapshot so that future scan/monitor runs can compare against it.

Baseline format (stored as JSON):
    {
        "created_at": "<ISO-8601 timestamp>",
        "n_observations": <int>,
        "features": {
            "<feature_name>": {
                "mean": <float>,
                "min":  <float>,
                "max":  <float>,
                "std":  <float>
            },
            ...
        }
    }

The numerical features used are the top-level scalar keys produced by
Feature 5 (extract_features()):
    cpu_percent
    memory_percent
    total_network_connections

Any additional top-level numeric keys in a feature observation are also
included automatically, making the baseline forward-compatible with future
Feature 5 additions.
"""

import json
import math
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Default path for the baseline file.  Callers (including tests) may override
# this by passing an explicit path to save_baseline() / load_baseline().
_DEFAULT_BASELINE_PATH = os.path.join(
    os.path.dirname(__file__),          # …/src/secml/detection/
    "..", "..", "..", "data", "baseline", "baseline.json"
)
DEFAULT_BASELINE_PATH: str = os.path.normpath(_DEFAULT_BASELINE_PATH)

# The top-level scalar numerical keys that Feature 5 always produces.
# Additional numeric top-level keys found in an observation are included too.
_KNOWN_FEATURE_KEYS: List[str] = [
    "cpu_percent",
    "memory_percent",
    "total_network_connections",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_numeric_features(observation: Dict[str, Any]) -> Dict[str, float]:
    """Pull numerical scalar values from a single feature observation.

    Only top-level keys with numeric (int/float) values that are not NaN or
    infinite are included.  Non-numeric and nested/dict/list values are skipped.

    Args:
        observation: A feature dict as returned by extract_features().

    Returns:
        Dict[str, float]: Mapping of feature name → float value.
    """
    result: Dict[str, float] = {}
    for key, val in observation.items():
        if not isinstance(val, (int, float)):
            continue
        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            continue
        result[key] = float(val)
    return result


def _compute_stats(values: List[float]) -> Dict[str, float]:
    """Compute mean, min, max, and std from a list of float values.

    Args:
        values: Non-empty list of float values.

    Returns:
        Dict[str, float]: Statistical summary.
    """
    n = len(values)
    mean = sum(values) / n
    minimum = min(values)
    maximum = max(values)

    # Population standard deviation (we have all observations; not a sample)
    variance = sum((v - mean) ** 2 for v in values) / n
    std = math.sqrt(variance)

    return {
        "mean": round(mean, 6),
        "min": round(minimum, 6),
        "max": round(maximum, 6),
        "std": round(std, 6),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_baseline(observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create a baseline from a collection of normal behavioral feature observations.

    Each observation should be a feature dict as produced by extract_features().
    The baseline captures per-feature statistics (mean, min, max, std) computed
    over all observations, representing the expected normal behavioral range.

    Args:
        observations: List of feature dicts representing normal behavior.
                      Must contain at least one observation with at least one
                      usable numerical feature.

    Returns:
        Dict[str, Any]: Baseline dict containing:
            - "created_at"    (str):  ISO-8601 UTC timestamp.
            - "n_observations" (int): Number of observations used.
            - "features"       (dict): Per-feature statistics.

    Raises:
        ValueError: If observations is empty or contains no usable numerical
                    features.
        TypeError: If observations is not a list.
    """
    if not isinstance(observations, list):
        raise TypeError(
            f"observations must be a list of feature dicts, got {type(observations).__name__}."
        )
    if len(observations) == 0:
        raise ValueError("At least one observation is required to create a baseline.")

    # Collect per-feature value lists across all observations
    feature_values: Dict[str, List[float]] = {}

    for i, obs in enumerate(observations):
        if not isinstance(obs, dict):
            raise TypeError(
                f"Each observation must be a dict, but item {i} is {type(obs).__name__}."
            )
        numeric = _extract_numeric_features(obs)
        for feature_name, value in numeric.items():
            feature_values.setdefault(feature_name, []).append(value)

    if not feature_values:
        raise ValueError(
            "No usable numerical features were found in the provided observations. "
            "Each observation must contain at least one top-level numeric key."
        )

    # Compute statistics for every feature seen
    features_stats: Dict[str, Dict[str, float]] = {
        name: _compute_stats(vals)
        for name, vals in feature_values.items()
    }

    return {
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "n_observations": len(observations),
        "features": features_stats,
    }


def save_baseline(
    baseline: Dict[str, Any],
    path: Optional[str] = None,
) -> str:
    """Persist a baseline dict to a JSON file.

    Args:
        baseline: Baseline dict as returned by create_baseline().
        path: Optional file path to write to.  Defaults to DEFAULT_BASELINE_PATH.

    Returns:
        str: Absolute path of the file that was written.

    Raises:
        TypeError: If baseline is not a dict.
        ValueError: If baseline is missing required keys.
        OSError: If the file cannot be written (propagated as-is).
    """
    if not isinstance(baseline, dict):
        raise TypeError(
            f"baseline must be a dict, got {type(baseline).__name__}."
        )
    required_keys = {"created_at", "n_observations", "features"}
    missing = required_keys - baseline.keys()
    if missing:
        raise ValueError(
            f"baseline is missing required keys: {sorted(missing)}. "
            "Pass a dict returned by create_baseline()."
        )

    target_path = path if path is not None else DEFAULT_BASELINE_PATH
    target_path = os.path.abspath(target_path)

    # Ensure the parent directory exists
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    with open(target_path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2)

    return target_path


def load_baseline(path: Optional[str] = None) -> Dict[str, Any]:
    """Load a previously saved baseline from a JSON file.

    Args:
        path: Optional file path to read from.  Defaults to DEFAULT_BASELINE_PATH.

    Returns:
        Dict[str, Any]: The baseline dict as originally created by create_baseline().

    Raises:
        FileNotFoundError: If the baseline file does not exist at path.
        ValueError: If the file contains invalid JSON or is missing required keys.
        OSError: If the file cannot be read (propagated as-is).
    """
    target_path = path if path is not None else DEFAULT_BASELINE_PATH
    target_path = os.path.abspath(target_path)

    if not os.path.isfile(target_path):
        raise FileNotFoundError(
            f"No baseline found at '{target_path}'. "
            "Create one first using create_baseline() and save_baseline()."
        )

    try:
        with open(target_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"The baseline file at '{target_path}' contains invalid JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected a JSON object in the baseline file, got {type(data).__name__}."
        )

    required_keys = {"created_at", "n_observations", "features"}
    missing = required_keys - data.keys()
    if missing:
        raise ValueError(
            f"Baseline file at '{target_path}' is missing required keys: {sorted(missing)}."
        )

    return data

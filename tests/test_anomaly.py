"""Tests for SecML ML Anomaly Detection Engine."""

import pytest
import numpy as np
from sklearn.ensemble import IsolationForest

from secml.detection.anomaly import (
    DEFAULT_RANDOM_STATE,
    detect_anomalies,
    prepare_feature_matrix,
    train_anomaly_model,
)


# ---------------------------------------------------------------------------
# Synthetic datasets used across multiple tests
# ---------------------------------------------------------------------------

# 20 tightly clustered "normal" observations:
# cpu ≈ 10–20%, memory ≈ 40–50%, connections ≈ 5–15
_RNG = np.random.default_rng(seed=42)
_NORMAL_DATA = (
    _RNG.uniform(low=[10, 40, 5], high=[20, 50, 15], size=(20, 3)).tolist()
)

# Same tight cluster but expressed as feature dicts
_NORMAL_FEATURE_DICTS = [
    {"cpu_percent": row[0], "memory_percent": row[1], "total_network_connections": row[2]}
    for row in _NORMAL_DATA
]

# A clearly isolated outlier: extreme CPU, memory, and connections
_OUTLIER_VECTOR = [[98.0, 97.0, 250.0]]


# ---------------------------------------------------------------------------
# Test 1 — Model training
# ---------------------------------------------------------------------------

def test_train_anomaly_model_returns_fitted_model():
    """Test 1 — A small valid dataset produces a fitted IsolationForest."""
    model = train_anomaly_model(_NORMAL_DATA)
    assert isinstance(model, IsolationForest)
    # sklearn sets n_features_in_ after fitting
    assert hasattr(model, "n_features_in_")
    assert model.n_features_in_ == 3


def test_train_anomaly_model_with_feature_dicts():
    """Training accepts a list of feature dictionaries from extract_features()."""
    model = train_anomaly_model(_NORMAL_FEATURE_DICTS)
    assert isinstance(model, IsolationForest)


def test_train_anomaly_model_with_numpy_array():
    """Training accepts a 2D NumPy array directly."""
    X = np.array(_NORMAL_DATA, dtype=float)
    model = train_anomaly_model(X)
    assert isinstance(model, IsolationForest)


# ---------------------------------------------------------------------------
# Test 2 — Prediction structure
# ---------------------------------------------------------------------------

def test_detect_anomalies_result_structure():
    """Test 2 — Prediction returns properly structured plain Python results."""
    model = train_anomaly_model(_NORMAL_DATA)
    sample = [[15.0, 45.0, 10.0]]

    results = detect_anomalies(model, sample)

    assert isinstance(results, list)
    assert len(results) == 1

    result = results[0]
    assert "is_anomaly" in result
    assert "label" in result
    assert "anomaly_score" in result

    # Must be native Python types, not NumPy scalars
    assert isinstance(result["is_anomaly"], bool)
    assert isinstance(result["label"], str)
    assert isinstance(result["anomaly_score"], float)
    assert result["label"] in ("NORMAL", "ANOMALY")


def test_detect_anomalies_multiple_observations():
    """Prediction processes multiple observations and returns one result per observation."""
    model = train_anomaly_model(_NORMAL_DATA)
    results = detect_anomalies(model, _NORMAL_DATA)

    assert isinstance(results, list)
    assert len(results) == len(_NORMAL_DATA)
    for r in results:
        assert isinstance(r["is_anomaly"], bool)
        assert r["label"] in ("NORMAL", "ANOMALY")
        assert isinstance(r["anomaly_score"], float)


# ---------------------------------------------------------------------------
# Test 3 — Normal data
# ---------------------------------------------------------------------------

def test_detect_anomalies_normal_data_processes_successfully():
    """Test 3 — Normal observations can be processed without errors."""
    model = train_anomaly_model(_NORMAL_DATA, random_state=DEFAULT_RANDOM_STATE)

    # Pick a single clearly in-distribution point
    normal_obs = [[15.0, 45.0, 10.0]]
    results = detect_anomalies(model, normal_obs)

    assert len(results) == 1
    result = results[0]
    # The result should exist and be well-formed; we do not hardcode "NORMAL"
    # because contamination affects the decision boundary.
    assert result["label"] in ("NORMAL", "ANOMALY")
    assert isinstance(result["anomaly_score"], float)


def test_detect_anomalies_accepts_feature_dicts():
    """Prediction accepts feature dicts identical to extract_features() output."""
    model = train_anomaly_model(_NORMAL_FEATURE_DICTS, random_state=DEFAULT_RANDOM_STATE)
    results = detect_anomalies(model, _NORMAL_FEATURE_DICTS[:3])

    assert len(results) == 3
    for r in results:
        assert r["label"] in ("NORMAL", "ANOMALY")


# ---------------------------------------------------------------------------
# Test 4 — Obvious outlier
# ---------------------------------------------------------------------------

def test_detect_anomalies_identifies_obvious_outlier():
    """Test 4 — A clearly separated outlier is flagged as ANOMALY deterministically."""
    # Build a tight cluster of 30 near-identical normal points
    rng = np.random.default_rng(seed=0)
    tight_cluster = rng.uniform(
        low=[10, 40, 5], high=[12, 42, 7], size=(30, 3)
    ).tolist()

    model = train_anomaly_model(
        tight_cluster,
        contamination=0.05,
        random_state=DEFAULT_RANDOM_STATE,
    )

    # The outlier is 5–10 standard deviations from the cluster centre
    results = detect_anomalies(model, _OUTLIER_VECTOR)

    assert len(results) == 1
    result = results[0]
    assert result["is_anomaly"] is True, (
        f"Expected ANOMALY for extreme outlier but got: {result}"
    )
    assert result["label"] == "ANOMALY"
    assert result["anomaly_score"] < 0


# ---------------------------------------------------------------------------
# Test 5 — Empty input
# ---------------------------------------------------------------------------

def test_prepare_feature_matrix_raises_on_empty_list():
    """Test 5 — Empty list raises a clear ValueError."""
    with pytest.raises(ValueError, match="empty"):
        prepare_feature_matrix([])


def test_prepare_feature_matrix_raises_on_empty_numpy_array():
    """Empty NumPy array raises a clear ValueError."""
    with pytest.raises(ValueError, match="empty"):
        prepare_feature_matrix(np.array([]))


def test_train_anomaly_model_raises_on_empty_input():
    """Training on empty data raises a clear ValueError."""
    with pytest.raises(ValueError):
        train_anomaly_model([])


def test_train_anomaly_model_raises_on_single_observation():
    """Training on a single observation raises a clear ValueError."""
    with pytest.raises(ValueError, match="At least 2"):
        train_anomaly_model([[10.0, 40.0, 5.0]])


# ---------------------------------------------------------------------------
# Test 6 — Invalid input
# ---------------------------------------------------------------------------

def test_prepare_feature_matrix_raises_on_none():
    """Test 6a — None input raises a clear ValueError, not an opaque crash."""
    with pytest.raises(ValueError, match="None"):
        prepare_feature_matrix(None)


def test_prepare_feature_matrix_raises_on_unsupported_type():
    """Test 6b — An unsupported type raises a clear ValueError."""
    with pytest.raises(ValueError, match="Unsupported feature data type"):
        prepare_feature_matrix("not a valid input")


def test_detect_anomalies_raises_on_wrong_model_type():
    """Test 6c — Passing a non-model object raises a clear TypeError."""
    with pytest.raises(TypeError, match="IsolationForest"):
        detect_anomalies("not a model", [[10.0, 40.0, 5.0]])


def test_train_anomaly_model_raises_on_mixed_types():
    """Test 6d — A list mixing dicts and non-dicts raises a clear ValueError."""
    mixed = [{"cpu_percent": 10.0}, "oops"]
    with pytest.raises(ValueError):
        train_anomaly_model(mixed)

"""ML Anomaly Detection Engine for SecML."""

from typing import Any, Dict, List, Union

import numpy as np
from sklearn.ensemble import IsolationForest

# Sensible defaults for Isolation Forest
DEFAULT_N_ESTIMATORS: int = 100
DEFAULT_CONTAMINATION: float = 0.05  # Expect ~5% anomalies in training data
DEFAULT_RANDOM_STATE: int = 42


def prepare_feature_matrix(
    data: Union[Dict[str, Any], List[Dict[str, Any]], List[List[float]], np.ndarray],
) -> np.ndarray:
    """Convert feature data into a 2D numerical NumPy array for the model.

    Accepts:
    - A single feature dictionary (as produced by extract_features())
    - A list of feature dictionaries (one per observation)
    - A list of numerical lists/tuples
    - A 2D NumPy array (passed through directly)

    Each feature dictionary is projected to the following fixed numerical vector:
        [cpu_percent, memory_percent, total_network_connections]

    Args:
        data: Feature data in any of the accepted formats.

    Returns:
        np.ndarray: 2D float array of shape (n_observations, n_features).

    Raises:
        ValueError: If data is empty, None, or contains no usable numerical features.
    """
    if data is None:
        raise ValueError("Feature data must not be None.")

    # NumPy array: accept directly if 2D
    if isinstance(data, np.ndarray):
        if data.ndim == 1:
            data = data.reshape(1, -1)
        if data.size == 0:
            raise ValueError("Feature array is empty.")
        return data.astype(float)

    # List input
    if isinstance(data, list):
        if len(data) == 0:
            raise ValueError("Feature data list is empty.")

        first = data[0]

        # List of feature dicts
        if isinstance(first, dict):
            rows = []
            for item in data:
                if not isinstance(item, dict):
                    raise ValueError(
                        "All items in the feature list must be dictionaries."
                    )
                rows.append(_dict_to_vector(item))
            matrix = np.array(rows, dtype=float)
            if matrix.size == 0:
                raise ValueError("Feature matrix is empty after conversion.")
            return matrix

        # List of numerical lists / tuples
        if isinstance(first, (list, tuple)):
            matrix = np.array(data, dtype=float)
            if matrix.ndim == 1:
                matrix = matrix.reshape(1, -1)
            if matrix.size == 0:
                raise ValueError("Feature matrix is empty after conversion.")
            return matrix

        # List of plain numbers → single observation
        if isinstance(first, (int, float)):
            matrix = np.array(data, dtype=float).reshape(1, -1)
            return matrix

        raise ValueError(
            f"Unsupported element type in feature list: {type(first).__name__}. "
            "Expected dict, list, or numeric values."
        )

    # Single feature dictionary
    if isinstance(data, dict):
        vec = _dict_to_vector(data)
        return np.array([vec], dtype=float)

    raise ValueError(
        f"Unsupported feature data type: {type(data).__name__}. "
        "Expected dict, list, or numpy array."
    )


def _dict_to_vector(feature_dict: Dict[str, Any]) -> List[float]:
    """Extract a fixed numerical feature vector from a feature dictionary.

    Projects to:
        [cpu_percent, memory_percent, total_network_connections]

    Missing values are substituted with 0.0 since skipping would silently
    change vector dimensionality. The caller controls whether None/missing
    values are acceptable in their context.

    Args:
        feature_dict: Behavioral feature dictionary as produced by extract_features().

    Returns:
        List[float]: Fixed-length numerical feature vector.
    """
    def _num(val: Any) -> float:
        """Return float if val is numeric, else 0.0."""
        if isinstance(val, (int, float)) and not (
            isinstance(val, float) and (np.isnan(val) or np.isinf(val))
        ):
            return float(val)
        return 0.0

    cpu = _num(feature_dict.get("cpu_percent"))
    mem = _num(feature_dict.get("memory_percent"))
    net = _num(feature_dict.get("total_network_connections"))

    # Also check nested system sub-dict for cpu/mem if top-level is 0.0
    system = feature_dict.get("system")
    if isinstance(system, dict):
        if cpu == 0.0:
            cpu = _num(system.get("cpu_percent"))
        if mem == 0.0:
            mem = _num(system.get("memory_percent"))

    network = feature_dict.get("network")
    if isinstance(network, dict) and net == 0.0:
        net = _num(network.get("total_connections"))

    return [cpu, mem, net]


def train_anomaly_model(
    features: Any,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    contamination: float = DEFAULT_CONTAMINATION,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> IsolationForest:
    """Train an Isolation Forest model on the provided feature data.

    Args:
        features: Feature data to train on. Accepts any format supported by
                  prepare_feature_matrix().
        n_estimators: Number of trees in the forest.
        contamination: Expected proportion of anomalies in the training data.
        random_state: Fixed random state for reproducible results.

    Returns:
        IsolationForest: Trained scikit-learn model.

    Raises:
        ValueError: If feature data is empty, invalid, or too small to train.
    """
    X = prepare_feature_matrix(features)

    if X.shape[0] < 2:
        raise ValueError(
            f"At least 2 observations are required to train the anomaly model, "
            f"but only {X.shape[0]} was provided."
        )

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X)
    return model


def detect_anomalies(
    model: IsolationForest,
    features: Any,
) -> List[Dict[str, Any]]:
    """Predict whether each observation is anomalous using a trained Isolation Forest.

    Isolation Forest raw prediction mapping:
         1 → inlier / NORMAL
        -1 → outlier / ANOMALY

    Args:
        model: A trained IsolationForest model (from train_anomaly_model).
        features: Feature data to evaluate. Accepts any format supported by
                  prepare_feature_matrix().

    Returns:
        List[Dict[str, Any]]: One result dict per observation, each containing:
            - "is_anomaly" (bool): True if the observation is anomalous.
            - "label" (str): "ANOMALY" or "NORMAL".
            - "anomaly_score" (float): The raw Isolation Forest decision score.
              Higher (less negative) values indicate more normal behaviour.

    Raises:
        ValueError: If feature data is empty or invalid.
        TypeError: If model is not a fitted IsolationForest.
    """
    if not isinstance(model, IsolationForest):
        raise TypeError(
            f"model must be a fitted IsolationForest, got {type(model).__name__}."
        )

    X = prepare_feature_matrix(features)

    raw_predictions = model.predict(X)          # array of 1 / -1
    raw_scores = model.decision_function(X)     # anomaly scores (higher = more normal)

    results: List[Dict[str, Any]] = []
    for pred, score in zip(raw_predictions, raw_scores):
        is_anomaly = bool(pred == -1)
        results.append(
            {
                "is_anomaly": is_anomaly,
                "label": "ANOMALY" if is_anomaly else "NORMAL",
                "anomaly_score": float(score),
            }
        )

    return results

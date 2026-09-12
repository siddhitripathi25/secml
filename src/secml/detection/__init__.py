"""Detection module for SecML."""

from secml.detection.features import extract_features
from secml.detection.rules import (
    HIGH_CPU_THRESHOLD,
    HIGH_MEMORY_THRESHOLD,
    HIGH_NETWORK_CONNECTIONS_THRESHOLD,
    HIGH_THREAD_COUNT_THRESHOLD,
    evaluate_rules,
)
from secml.detection.anomaly import (
    DEFAULT_CONTAMINATION,
    DEFAULT_N_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
    detect_anomalies,
    prepare_feature_matrix,
    train_anomaly_model,
)
from secml.detection.baseline import (
    DEFAULT_BASELINE_PATH,
    create_baseline,
    load_baseline,
    save_baseline,
)

__all__ = [
    # Feature extraction
    "extract_features",
    # Rule engine
    "evaluate_rules",
    "HIGH_CPU_THRESHOLD",
    "HIGH_MEMORY_THRESHOLD",
    "HIGH_NETWORK_CONNECTIONS_THRESHOLD",
    "HIGH_THREAD_COUNT_THRESHOLD",
    # ML anomaly engine
    "prepare_feature_matrix",
    "train_anomaly_model",
    "detect_anomalies",
    "DEFAULT_N_ESTIMATORS",
    "DEFAULT_CONTAMINATION",
    "DEFAULT_RANDOM_STATE",
    # Baseline system
    "create_baseline",
    "save_baseline",
    "load_baseline",
    "DEFAULT_BASELINE_PATH",
]

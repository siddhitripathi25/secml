"""Detection module for SecML."""

from secml.detection.features import extract_features
from secml.detection.rules import (
    HIGH_CPU_THRESHOLD,
    HIGH_MEMORY_THRESHOLD,
    HIGH_NETWORK_CONNECTIONS_THRESHOLD,
    HIGH_THREAD_COUNT_THRESHOLD,
    evaluate_rules,
)

__all__ = [
    "extract_features",
    "evaluate_rules",
    "HIGH_CPU_THRESHOLD",
    "HIGH_MEMORY_THRESHOLD",
    "HIGH_NETWORK_CONNECTIONS_THRESHOLD",
    "HIGH_THREAD_COUNT_THRESHOLD",
]

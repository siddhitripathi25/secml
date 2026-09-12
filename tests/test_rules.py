"""Tests for SecML Rule-Based Detection Engine."""

from secml.detection.features import extract_features
from secml.detection.rules import (
    HIGH_CPU_THRESHOLD,
    HIGH_MEMORY_THRESHOLD,
    HIGH_NETWORK_CONNECTIONS_THRESHOLD,
    HIGH_THREAD_COUNT_THRESHOLD,
    evaluate_rules,
)


def test_normal_behavior_no_detections():
    """Test 1 — Normal behavior: Normal feature values produce no detections."""
    normal_features = {
        "cpu_percent": 15.0,
        "memory_percent": 45.0,
        "total_network_connections": 10,
        "processes": [
            {
                "pid": 100,
                "name": "python",
                "exe": "/usr/bin/python3",
                "cpu_percent": 5.0,
                "memory_percent": 2.0,
                "num_threads": 4,
            }
        ],
    }

    detections = evaluate_rules(normal_features)
    assert isinstance(detections, list)
    assert len(detections) == 0


def test_high_cpu_detection():
    """Test 2 — High CPU: Feature data above CPU threshold triggers HIGH_CPU_USAGE."""
    high_cpu_features = {
        "cpu_percent": 95.4,
        "memory_percent": 30.0,
    }

    detections = evaluate_rules(high_cpu_features)
    assert isinstance(detections, list)
    assert len(detections) >= 1

    cpu_detection = next((d for d in detections if d["rule_id"] == "HIGH_CPU_USAGE"), None)
    assert cpu_detection is not None
    assert cpu_detection["severity"] in ["LOW", "MEDIUM", "HIGH"]
    assert isinstance(cpu_detection["message"], str)
    assert len(cpu_detection["message"]) > 0
    assert "evidence" in cpu_detection
    assert cpu_detection["evidence"]["cpu_percent"] == 95.4


def test_high_memory_detection():
    """Test 3 — High memory: Feature data above memory threshold triggers HIGH_MEMORY_USAGE."""
    high_mem_features = {
        "cpu_percent": 10.0,
        "memory_percent": 92.5,
    }

    detections = evaluate_rules(high_mem_features)
    assert isinstance(detections, list)
    assert len(detections) >= 1

    mem_detection = next((d for d in detections if d["rule_id"] == "HIGH_MEMORY_USAGE"), None)
    assert mem_detection is not None
    assert mem_detection["severity"] in ["LOW", "MEDIUM", "HIGH"]
    assert isinstance(mem_detection["message"], str)
    assert "evidence" in mem_detection
    assert mem_detection["evidence"]["memory_percent"] == 92.5


def test_suspicious_network_behavior_detection():
    """Test 4 — Suspicious network behavior: High connection count triggers HIGH_NETWORK_ACTIVITY."""
    high_net_features = {
        "total_network_connections": 120,
    }

    detections = evaluate_rules(high_net_features)
    assert isinstance(detections, list)
    assert len(detections) >= 1

    net_detection = next((d for d in detections if d["rule_id"] == "HIGH_NETWORK_ACTIVITY"), None)
    assert net_detection is not None
    assert net_detection["severity"] in ["LOW", "MEDIUM", "HIGH"]
    assert isinstance(net_detection["message"], str)
    assert "evidence" in net_detection
    assert net_detection["evidence"]["connection_count"] == 120


def test_multiple_rules_detection():
    """Test 5 — Multiple rules: Data triggering multiple rules returns multiple detections."""
    multi_features = {
        "cpu_percent": 90.0,
        "memory_percent": 88.0,
        "total_network_connections": 75,
        "processes": [
            {
                "pid": 500,
                "name": "suspicious_proc",
                "exe": "/tmp/miner",
                "cpu_percent": 95.0,
                "num_threads": 150,
            }
        ],
    }

    detections = evaluate_rules(multi_features)
    assert isinstance(detections, list)
    assert len(detections) >= 3

    rule_ids = {d["rule_id"] for d in detections}
    assert "HIGH_CPU_USAGE" in rule_ids
    assert "HIGH_MEMORY_USAGE" in rule_ids
    assert "HIGH_NETWORK_ACTIVITY" in rule_ids
    assert "SUSPICIOUS_PROCESS_BEHAVIOR" in rule_ids


def test_missing_feature_data_graceful():
    """Test 6 — Missing feature data: Engine does not crash on empty or partial payloads."""
    assert evaluate_rules(None) == []
    assert evaluate_rules({}) == []
    assert evaluate_rules({"system": None, "processes": None}) == []
    assert evaluate_rules({"cpu_percent": None, "memory_percent": None}) == []


def test_extract_features_integration():
    """Verify integration between Feature 5 (extract_features) and Feature 6 (evaluate_rules)."""
    system_data = {"cpu_percent": 98.0, "memory": {"percent": 91.0}}
    process_data = [{"pid": 12, "name": "test", "num_threads": 5}]
    network_data = [{"status": "ESTABLISHED"}] * 60

    features = extract_features(
        system_info=system_data,
        processes=process_data,
        network_connections=network_data,
    )

    detections = evaluate_rules(features)
    assert len(detections) >= 3
    rule_ids = {d["rule_id"] for d in detections}
    assert "HIGH_CPU_USAGE" in rule_ids
    assert "HIGH_MEMORY_USAGE" in rule_ids
    assert "HIGH_NETWORK_ACTIVITY" in rule_ids

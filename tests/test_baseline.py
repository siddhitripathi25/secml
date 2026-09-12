"""Tests for SecML Baseline System (Feature 9)."""

import json
import math
import os

import pytest

from secml.detection.baseline import (
    create_baseline,
    load_baseline,
    save_baseline,
)


# ---------------------------------------------------------------------------
# Shared synthetic observations
# ---------------------------------------------------------------------------

# Simple feature observations with known, easy-to-verify statistics.
# cpu values: [10, 20, 30]  → mean=20, min=10, max=30, std≈8.165
# mem values: [40, 50, 60]  → mean=50, min=40, max=60, std≈8.165
# net values: [5, 10, 15]   → mean=10, min=5,  max=15, std≈4.082
_SIMPLE_OBSERVATIONS = [
    {"cpu_percent": 10.0, "memory_percent": 40.0, "total_network_connections": 5},
    {"cpu_percent": 20.0, "memory_percent": 50.0, "total_network_connections": 10},
    {"cpu_percent": 30.0, "memory_percent": 60.0, "total_network_connections": 15},
]


# ---------------------------------------------------------------------------
# Test 1 — Create baseline
# ---------------------------------------------------------------------------

def test_create_baseline_returns_dict():
    """Test 1 — create_baseline() succeeds on a small valid dataset."""
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)

    assert isinstance(baseline, dict)
    assert "created_at" in baseline
    assert "n_observations" in baseline
    assert "features" in baseline
    assert baseline["n_observations"] == 3


def test_create_baseline_single_observation():
    """A single observation is the minimum required; should succeed."""
    baseline = create_baseline([{"cpu_percent": 50.0}])
    assert isinstance(baseline, dict)
    assert baseline["n_observations"] == 1


# ---------------------------------------------------------------------------
# Test 2 — Statistical values
# ---------------------------------------------------------------------------

def test_baseline_statistics_are_correct():
    """Test 2 — Per-feature statistics match expected values."""
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)
    features = baseline["features"]

    # cpu_percent: [10, 20, 30]
    cpu = features["cpu_percent"]
    assert math.isclose(cpu["mean"], 20.0, abs_tol=1e-4)
    assert math.isclose(cpu["min"], 10.0, abs_tol=1e-4)
    assert math.isclose(cpu["max"], 30.0, abs_tol=1e-4)
    # Population std: sqrt(((10-20)²+(20-20)²+(30-20)²)/3) = sqrt(200/3) ≈ 8.1650
    assert math.isclose(cpu["std"], math.sqrt(200 / 3), abs_tol=1e-3)

    # memory_percent: [40, 50, 60]
    mem = features["memory_percent"]
    assert math.isclose(mem["mean"], 50.0, abs_tol=1e-4)
    assert math.isclose(mem["min"], 40.0, abs_tol=1e-4)
    assert math.isclose(mem["max"], 60.0, abs_tol=1e-4)
    assert math.isclose(mem["std"], math.sqrt(200 / 3), abs_tol=1e-3)

    # total_network_connections: [5, 10, 15]
    net = features["total_network_connections"]
    assert math.isclose(net["mean"], 10.0, abs_tol=1e-4)
    assert math.isclose(net["min"], 5.0, abs_tol=1e-4)
    assert math.isclose(net["max"], 15.0, abs_tol=1e-4)
    assert math.isclose(net["std"], math.sqrt(50 / 3), abs_tol=1e-3)


def test_single_observation_has_zero_std():
    """A single observation should produce std=0.0 (no variance)."""
    baseline = create_baseline([{"cpu_percent": 42.0}])
    assert math.isclose(baseline["features"]["cpu_percent"]["std"], 0.0, abs_tol=1e-9)
    assert math.isclose(baseline["features"]["cpu_percent"]["mean"], 42.0, abs_tol=1e-9)


def test_statistics_keys_are_present():
    """Test 2b — Each feature entry must contain mean, min, max, std."""
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)
    for feat_name, stats in baseline["features"].items():
        assert "mean" in stats, f"'mean' missing for feature {feat_name}"
        assert "min" in stats, f"'min' missing for feature {feat_name}"
        assert "max" in stats, f"'max' missing for feature {feat_name}"
        assert "std" in stats, f"'std' missing for feature {feat_name}"


# ---------------------------------------------------------------------------
# Test 3 — Save baseline (uses tmp_path to avoid touching data/baseline/)
# ---------------------------------------------------------------------------

def test_save_baseline_creates_file(tmp_path):
    """Test 3 — save_baseline() writes a file and it contains valid JSON."""
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)
    target = str(tmp_path / "test_baseline.json")

    returned_path = save_baseline(baseline, path=target)

    # File must exist
    assert os.path.isfile(returned_path)

    # Content must be valid JSON
    with open(returned_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    assert isinstance(data, dict)
    assert "features" in data


def test_save_baseline_creates_parent_directories(tmp_path):
    """save_baseline() should create missing parent directories automatically."""
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)
    nested_path = str(tmp_path / "deep" / "nested" / "dir" / "baseline.json")

    returned_path = save_baseline(baseline, path=nested_path)

    assert os.path.isfile(returned_path)


def test_save_baseline_returns_absolute_path(tmp_path):
    """save_baseline() always returns an absolute path string."""
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)
    target = str(tmp_path / "b.json")

    returned_path = save_baseline(baseline, path=target)

    assert os.path.isabs(returned_path)


# ---------------------------------------------------------------------------
# Test 4 — Load baseline
# ---------------------------------------------------------------------------

def test_load_baseline_roundtrip(tmp_path):
    """Test 4 — A saved baseline loads back with identical values."""
    original = create_baseline(_SIMPLE_OBSERVATIONS)
    target = str(tmp_path / "baseline.json")

    save_baseline(original, path=target)
    loaded = load_baseline(path=target)

    assert loaded["n_observations"] == original["n_observations"]
    assert loaded["created_at"] == original["created_at"]

    for feat_name, stats in original["features"].items():
        assert feat_name in loaded["features"]
        loaded_stats = loaded["features"][feat_name]
        for stat_key, stat_val in stats.items():
            assert math.isclose(loaded_stats[stat_key], stat_val, abs_tol=1e-6), (
                f"Mismatch for {feat_name}.{stat_key}: "
                f"expected {stat_val}, got {loaded_stats[stat_key]}"
            )


# ---------------------------------------------------------------------------
# Test 5 — Missing baseline
# ---------------------------------------------------------------------------

def test_load_baseline_raises_file_not_found(tmp_path):
    """Test 5 — Loading a non-existent baseline raises FileNotFoundError."""
    missing_path = str(tmp_path / "does_not_exist.json")

    with pytest.raises(FileNotFoundError, match="No baseline found"):
        load_baseline(path=missing_path)


# ---------------------------------------------------------------------------
# Test 6 — Empty / invalid input
# ---------------------------------------------------------------------------

def test_create_baseline_raises_on_empty_list():
    """Test 6a — Empty list raises ValueError."""
    with pytest.raises(ValueError, match="At least one observation"):
        create_baseline([])


def test_create_baseline_raises_on_non_list():
    """Test 6b — Non-list input raises TypeError."""
    with pytest.raises(TypeError, match="must be a list"):
        create_baseline({"cpu_percent": 10.0})  # type: ignore[arg-type]


def test_create_baseline_raises_when_no_numeric_features():
    """Test 6c — Observations with no numeric top-level values raise ValueError."""
    non_numeric_obs = [
        {"platform": "Darwin", "processes": [{"pid": 1}], "network": {}},
    ]
    with pytest.raises(ValueError, match="No usable numerical features"):
        create_baseline(non_numeric_obs)


def test_create_baseline_raises_on_non_dict_observation():
    """Test 6d — A non-dict item inside the list raises TypeError."""
    with pytest.raises(TypeError, match="Each observation must be a dict"):
        create_baseline([{"cpu_percent": 5.0}, "not a dict"])


def test_load_baseline_raises_on_invalid_json(tmp_path):
    """Test 6e — A file with invalid JSON raises ValueError with a clear message."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("this is { not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        load_baseline(path=str(bad_file))


def test_load_baseline_raises_on_missing_keys(tmp_path):
    """Test 6f — A JSON file missing required baseline keys raises ValueError."""
    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"created_at": "2024-01-01T00:00:00+00:00"}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required keys"):
        load_baseline(path=str(incomplete))


def test_save_baseline_raises_on_invalid_baseline():
    """Test 6g — save_baseline() with a dict missing required keys raises ValueError."""
    bad_baseline = {"created_at": "2024-01-01T00:00:00+00:00"}  # missing n_observations, features

    with pytest.raises(ValueError, match="missing required keys"):
        save_baseline(bad_baseline, path="/tmp/should_not_be_written.json")


def test_create_baseline_skips_nan_and_inf():
    """NaN and Inf values are silently skipped; valid values in the same obs are kept."""
    import math as _math
    obs = [
        {"cpu_percent": float("nan"), "memory_percent": 50.0},
        {"cpu_percent": float("inf"), "memory_percent": 60.0},
        {"cpu_percent": 30.0, "memory_percent": 70.0},
    ]
    baseline = create_baseline(obs)
    # Only the third observation has a valid cpu_percent
    assert baseline["features"]["cpu_percent"]["mean"] == 30.0
    # All three have valid memory_percent
    assert _math.isclose(baseline["features"]["memory_percent"]["mean"], 60.0, abs_tol=1e-4)


# ---------------------------------------------------------------------------
# Test 7 — Multiple features
# ---------------------------------------------------------------------------

def test_create_baseline_multiple_features():
    """Test 7 — All top-level numeric keys get their own baseline statistics."""
    observations = [
        {
            "cpu_percent": 10.0,
            "memory_percent": 40.0,
            "total_network_connections": 5,
        },
        {
            "cpu_percent": 20.0,
            "memory_percent": 60.0,
            "total_network_connections": 15,
        },
    ]
    baseline = create_baseline(observations)
    features = baseline["features"]

    assert "cpu_percent" in features
    assert "memory_percent" in features
    assert "total_network_connections" in features

    # Each feature must have its own independent stats
    assert features["cpu_percent"]["mean"] != features["memory_percent"]["mean"]
    assert features["cpu_percent"]["max"] == 20.0
    assert features["memory_percent"]["max"] == 60.0
    assert features["total_network_connections"]["max"] == 15.0


def test_baseline_n_observations_reflects_input():
    """n_observations in the baseline must equal the number of input dicts."""
    obs = [{"cpu_percent": float(i)} for i in range(10)]
    baseline = create_baseline(obs)
    assert baseline["n_observations"] == 10


def test_baseline_created_at_is_iso_timestamp():
    """created_at must be a parseable ISO-8601 string."""
    from datetime import datetime
    baseline = create_baseline(_SIMPLE_OBSERVATIONS)
    # datetime.fromisoformat raises ValueError if the string is invalid
    parsed = datetime.fromisoformat(baseline["created_at"])
    assert parsed is not None

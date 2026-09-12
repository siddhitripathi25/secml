"""Tests for SecML CLI — Features 1 and 10."""

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from secml.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Existing CLI foundation tests (Feature 1) — must remain passing
# ---------------------------------------------------------------------------

def test_cli_starts():
    """Verify that the CLI starts successfully."""
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "SecML" in result.stdout


def test_cli_help():
    """Verify that --help displays help and CLI description."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AI/ML-Powered Behavioral Security Analyzer for the Terminal" in result.stdout


def test_cli_version():
    """Verify that --version returns 0.1.0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


# ---------------------------------------------------------------------------
# Helper: default mocks for a clean scan
# ---------------------------------------------------------------------------

_FAKE_SYSTEM_INFO = {
    "platform": "Darwin",
    "os_release": "23.0.0",
    "architecture": "arm64",
    "cpu_count": 8,
    "cpu_percent": 10.0,
    "memory": {"total": 17179869184, "available": 8589934592, "percent": 30.0},
    "disk": {"total": 500000000000, "free": 250000000000, "percent": 50.0},
    "boot_time": "2024-01-01T00:00:00+00:00",
}

_FAKE_PROCESSES = [
    {
        "pid": 1,
        "name": "launchd",
        "exe": "/sbin/launchd",
        "username": "root",
        "cpu_percent": 0.1,
        "memory_percent": 0.2,
        "create_time": "2024-01-01T00:00:00+00:00",
        "status": "sleeping",
        "num_threads": 4,
        "cmdline": ["/sbin/launchd"],
    }
]

_FAKE_NETWORK = [
    {"fd": 10, "family": "AF_INET", "type": "SOCK_STREAM",
     "local_address": "127.0.0.1:8080", "remote_address": None,
     "status": "LISTEN", "pid": 1},
]

_FAKE_FEATURES = {
    "cpu_percent": 10.0,
    "memory_percent": 30.0,
    "total_network_connections": 1,
    "processes": _FAKE_PROCESSES,
    "network": {"total_connections": 1, "established_connections": 0, "connections": _FAKE_NETWORK},
    "system": {"cpu_percent": 10.0, "memory_percent": 30.0},
}

_FAKE_RISK = {
    "score": 8,
    "level": "SAFE",
    "rule_score": 8,
    "anomaly_score": 0,
}


def _make_scan_patches(
    system_info=None,
    processes=None,
    network=None,
    features=None,
    rule_detections=None,
    anomaly_results=None,
    risk=None,
    baseline_side_effect=None,
    anomaly_side_effect=None,
):
    """Return a dict of patch kwargs suitable for @patch decorators."""
    return dict(
        system_info=system_info if system_info is not None else _FAKE_SYSTEM_INFO,
        processes=processes if processes is not None else _FAKE_PROCESSES,
        network=network if network is not None else _FAKE_NETWORK,
        features=features if features is not None else _FAKE_FEATURES,
        rule_detections=rule_detections if rule_detections is not None else [],
        anomaly_results=anomaly_results if anomaly_results is not None else [],
        risk=risk if risk is not None else _FAKE_RISK,
        baseline_side_effect=baseline_side_effect,
        anomaly_side_effect=anomaly_side_effect,
    )


def _invoke_scan_with_mocks(
    system_info=None,
    processes=None,
    network=None,
    features=None,
    rule_detections=None,
    anomaly_results=None,
    risk=None,
    baseline_side_effect=FileNotFoundError("no baseline"),
    train_return=None,
    detect_return=None,
):
    """Invoke `secml scan` with all heavy components mocked out."""
    cfg = _make_scan_patches(
        system_info=system_info,
        processes=processes,
        network=network,
        features=features,
        rule_detections=rule_detections,
        anomaly_results=anomaly_results,
        risk=risk,
    )
    mock_model = MagicMock()

    with patch("secml.cli.get_system_info", return_value=cfg["system_info"]), \
         patch("secml.cli.get_processes", return_value=cfg["processes"]), \
         patch("secml.cli.get_network_connections", return_value=cfg["network"]), \
         patch("secml.cli.extract_features", return_value=cfg["features"]), \
         patch("secml.cli.evaluate_rules", return_value=cfg["rule_detections"]), \
         patch("secml.cli.load_baseline",
               side_effect=baseline_side_effect if baseline_side_effect else None,
               return_value=None if baseline_side_effect else {
                   "created_at": "2024-01-01T00:00:00+00:00",
                   "n_observations": 5,
                   "features": {
                       "cpu_percent": {"mean": 10.0, "min": 5.0, "max": 20.0, "std": 3.0},
                       "memory_percent": {"mean": 30.0, "min": 25.0, "max": 40.0, "std": 5.0},
                       "total_network_connections": {"mean": 1.0, "min": 0.0, "max": 3.0, "std": 1.0},
                   },
               }), \
         patch("secml.cli.train_anomaly_model",
               return_value=train_return if train_return is not None else mock_model), \
         patch("secml.cli.detect_anomalies",
               return_value=detect_return if detect_return is not None else cfg["anomaly_results"]), \
         patch("secml.cli.calculate_risk_score", return_value=cfg["risk"]):
        return runner.invoke(app, ["scan"])


# ---------------------------------------------------------------------------
# Test 1 — Scan command exists
# ---------------------------------------------------------------------------

def test_scan_command_exists_in_help():
    """Test 1 — 'scan' appears in the CLI help output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout.lower()


def test_scan_command_is_invocable():
    """Test 1b — The scan command can be invoked without crashing."""
    result = _invoke_scan_with_mocks()
    # exit_code 0 (SAFE) or 1 (HIGH/CRITICAL); either is acceptable for invocability
    assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# Test 2 — Successful scan flow
# ---------------------------------------------------------------------------

def test_scan_calls_all_components():
    """Test 2 — The scan orchestrates all pipeline components."""
    with patch("secml.cli.get_system_info", return_value=_FAKE_SYSTEM_INFO) as mock_sys, \
         patch("secml.cli.get_processes", return_value=_FAKE_PROCESSES) as mock_proc, \
         patch("secml.cli.get_network_connections", return_value=_FAKE_NETWORK) as mock_net, \
         patch("secml.cli.extract_features", return_value=_FAKE_FEATURES) as mock_feat, \
         patch("secml.cli.evaluate_rules", return_value=[]) as mock_rules, \
         patch("secml.cli.load_baseline", side_effect=FileNotFoundError("no baseline")), \
         patch("secml.cli.train_anomaly_model", return_value=MagicMock()), \
         patch("secml.cli.detect_anomalies", return_value=[]) as mock_detect, \
         patch("secml.cli.calculate_risk_score", return_value=_FAKE_RISK) as mock_score:

        result = runner.invoke(app, ["scan"])

        mock_sys.assert_called_once()
        mock_proc.assert_called_once()
        mock_net.assert_called_once()
        mock_feat.assert_called_once()
        mock_rules.assert_called_once()
        mock_score.assert_called_once()
        # ML skipped because baseline raised FileNotFoundError
        mock_detect.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3 — Risk result displayed
# ---------------------------------------------------------------------------

def test_scan_displays_risk_score():
    """Test 3 — The scan output contains the risk score and level."""
    risk = {"score": 72, "level": "HIGH", "rule_score": 50, "anomaly_score": 22}
    result = _invoke_scan_with_mocks(risk=risk)

    assert "72" in result.stdout
    assert "HIGH" in result.stdout


def test_scan_displays_safe_score():
    """Test 3b — SAFE scan also shows score in output."""
    risk = {"score": 0, "level": "SAFE", "rule_score": 0, "anomaly_score": 0}
    result = _invoke_scan_with_mocks(risk=risk)

    assert "0" in result.stdout
    assert "SAFE" in result.stdout


# ---------------------------------------------------------------------------
# Test 4 — Detection results displayed
# ---------------------------------------------------------------------------

def test_scan_displays_rule_detections():
    """Test 4 — Triggered rule detections appear in scan output."""
    detections = [
        {
            "rule_id": "HIGH_CPU_USAGE",
            "severity": "MEDIUM",
            "message": "CPU is at 90%",
            "evidence": {"cpu_percent": 90.0},
        }
    ]
    result = _invoke_scan_with_mocks(rule_detections=detections)

    assert "HIGH_CPU_USAGE" in result.stdout


def test_scan_no_detections_shows_clean_message():
    """Test 4b — Zero detections shows a clean 'no patterns' message."""
    result = _invoke_scan_with_mocks(rule_detections=[])
    # The display helper prints this when there are no detections
    assert "No suspicious patterns detected" in result.stdout


# ---------------------------------------------------------------------------
# Test 5 — Missing baseline
# ---------------------------------------------------------------------------

def test_scan_handles_missing_baseline_gracefully():
    """Test 5 — Missing baseline does not crash; user sees a friendly message."""
    result = _invoke_scan_with_mocks(
        baseline_side_effect=FileNotFoundError("no baseline"),
    )

    # Must not crash
    assert result.exit_code in (0, 1)
    # Must not expose a raw traceback
    assert "Traceback" not in result.stdout
    # Should mention baseline or ML being unavailable
    assert any(word in result.stdout for word in ("baseline", "Baseline", "ML", "skipped"))


def test_scan_handles_corrupt_baseline_gracefully():
    """Test 5b — Corrupt baseline (ValueError) is handled without crash."""
    result = _invoke_scan_with_mocks(
        baseline_side_effect=ValueError("invalid JSON"),
    )
    assert result.exit_code in (0, 1)
    assert "Traceback" not in result.stdout


# ---------------------------------------------------------------------------
# Test 6 — Collector failure
# ---------------------------------------------------------------------------

def test_scan_handles_system_collector_failure():
    """Test 6a — OSError in system collector is handled gracefully."""
    with patch("secml.cli.get_system_info", side_effect=OSError("permission denied")), \
         patch("secml.cli.get_processes", return_value=_FAKE_PROCESSES), \
         patch("secml.cli.get_network_connections", return_value=_FAKE_NETWORK), \
         patch("secml.cli.extract_features", return_value=_FAKE_FEATURES), \
         patch("secml.cli.evaluate_rules", return_value=[]), \
         patch("secml.cli.load_baseline", side_effect=FileNotFoundError("no baseline")), \
         patch("secml.cli.train_anomaly_model", return_value=MagicMock()), \
         patch("secml.cli.detect_anomalies", return_value=[]), \
         patch("secml.cli.calculate_risk_score", return_value=_FAKE_RISK):

        result = runner.invoke(app, ["scan"])

        assert result.exit_code in (0, 1)
        assert "Traceback" not in result.stdout


def test_scan_handles_network_collector_failure():
    """Test 6b — PermissionError in network collector is handled gracefully."""
    with patch("secml.cli.get_system_info", return_value=_FAKE_SYSTEM_INFO), \
         patch("secml.cli.get_processes", return_value=_FAKE_PROCESSES), \
         patch("secml.cli.get_network_connections", side_effect=PermissionError("denied")), \
         patch("secml.cli.extract_features", return_value=_FAKE_FEATURES), \
         patch("secml.cli.evaluate_rules", return_value=[]), \
         patch("secml.cli.load_baseline", side_effect=FileNotFoundError("no baseline")), \
         patch("secml.cli.train_anomaly_model", return_value=MagicMock()), \
         patch("secml.cli.detect_anomalies", return_value=[]), \
         patch("secml.cli.calculate_risk_score", return_value=_FAKE_RISK):

        result = runner.invoke(app, ["scan"])

        assert result.exit_code in (0, 1)
        assert "Traceback" not in result.stdout


# ---------------------------------------------------------------------------
# Test — Exit code reflects risk level
# ---------------------------------------------------------------------------

def test_scan_exits_0_for_safe():
    """SAFE risk level → exit code 0."""
    risk = {"score": 5, "level": "SAFE", "rule_score": 5, "anomaly_score": 0}
    result = _invoke_scan_with_mocks(risk=risk)
    assert result.exit_code == 0


def test_scan_exits_1_for_high():
    """HIGH risk level → exit code 1 (signals issue to calling scripts)."""
    risk = {"score": 75, "level": "HIGH", "rule_score": 55, "anomaly_score": 20}
    result = _invoke_scan_with_mocks(risk=risk)
    assert result.exit_code == 1


def test_scan_exits_1_for_critical():
    """CRITICAL risk level → exit code 1."""
    risk = {"score": 95, "level": "CRITICAL", "rule_score": 70, "anomaly_score": 25}
    result = _invoke_scan_with_mocks(risk=risk)
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Monitor Command Tests
# ---------------------------------------------------------------------------

def test_monitor_command_exists_in_help():
    """Verify that 'monitor' appears in the CLI help output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "monitor" in result.stdout.lower()


def test_monitor_stops_on_interrupt():
    """Verify that monitor loop exits gracefully on Ctrl+C (KeyboardInterrupt)."""
    with patch("secml.cli._run_core_pipeline", return_value=_FAKE_RISK) as mock_pipeline, \
         patch("secml.cli.time.sleep", side_effect=KeyboardInterrupt):
        
        result = runner.invoke(app, ["monitor"])
        
        # It should run the pipeline once before hitting sleep
        mock_pipeline.assert_called_once()
        
        # Exit code should be 0 because it's a graceful exit
        assert result.exit_code == 0
        assert "Monitor mode stopped successfully" in result.stdout


def test_monitor_uses_interval_option():
    """Verify that monitor passes the interval option to sleep correctly."""
    with patch("secml.cli._run_core_pipeline", return_value=_FAKE_RISK), \
         patch("secml.cli.time.sleep", side_effect=KeyboardInterrupt) as mock_sleep:
        
        # Pass interval of 10
        result = runner.invoke(app, ["monitor", "--interval", "10"])
        
        assert result.exit_code == 0
        # Check that sleep was called with the custom interval
        mock_sleep.assert_called_once_with(10)
        assert "Interval: 10 seconds" in result.stdout


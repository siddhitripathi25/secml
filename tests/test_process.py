"""Tests for process telemetry collector."""

from unittest.mock import MagicMock, patch
import psutil
from secml.collectors.process import get_processes


def test_get_processes_structure():
    """Verify that get_processes returns a list of dictionaries with expected structure."""
    procs = get_processes()
    assert isinstance(procs, list)
    assert len(procs) > 0

    expected_keys = {
        "pid",
        "name",
        "exe",
        "username",
        "cpu_percent",
        "memory_percent",
        "create_time",
        "status",
        "num_threads",
        "cmdline",
    }

    for proc in procs:
        assert isinstance(proc, dict)
        assert expected_keys.issubset(proc.keys())

        # PID must be an integer
        assert isinstance(proc["pid"], int)

        # Types of optional fields if present
        if proc["name"] is not None:
            assert isinstance(proc["name"], str)

        if proc["exe"] is not None:
            assert isinstance(proc["exe"], str)

        if proc["username"] is not None:
            assert isinstance(proc["username"], str)

        if proc["cpu_percent"] is not None:
            assert isinstance(proc["cpu_percent"], (int, float))

        if proc["memory_percent"] is not None:
            assert isinstance(proc["memory_percent"], (int, float))

        if proc["status"] is not None:
            assert isinstance(proc["status"], str)

        if proc["num_threads"] is not None:
            assert isinstance(proc["num_threads"], int)

        if proc["cmdline"] is not None:
            assert isinstance(proc["cmdline"], list)
            for arg in proc["cmdline"]:
                assert isinstance(arg, str)


def test_get_processes_handles_exceptions_gracefully():
    """Verify that disappearing/inaccessible processes are handled without crashing."""
    mock_valid_proc = MagicMock()
    mock_valid_proc.info = {
        "pid": 100,
        "name": "test_proc",
        "exe": "/bin/test_proc",
        "username": "user",
        "cpu_percent": 2.5,
        "memory_percent": 1.1,
        "create_time": 1700000000.0,
        "status": "running",
        "num_threads": 4,
        "cmdline": ["/bin/test_proc", "--arg"],
    }

    # Mock process that raises AccessDenied on accessing info
    mock_denied_proc = MagicMock()
    type(mock_denied_proc).info = property(
        lambda self: (_ for _ in ()).throw(psutil.AccessDenied(pid=101))
    )

    # Mock process that raises NoSuchProcess on accessing info
    mock_no_such_proc = MagicMock()
    type(mock_no_such_proc).info = property(
        lambda self: (_ for _ in ()).throw(psutil.NoSuchProcess(pid=102))
    )

    # Mock process with AccessDenied in individual attributes
    mock_partial_proc = MagicMock()
    mock_partial_proc.info = {
        "pid": 103,
        "name": "partial_proc",
        "exe": psutil.AccessDenied(pid=103),
        "username": psutil.AccessDenied(pid=103),
        "cpu_percent": None,
        "memory_percent": None,
        "create_time": None,
        "status": "sleeping",
        "num_threads": 1,
        "cmdline": psutil.AccessDenied(pid=103),
    }

    mock_procs = [
        mock_valid_proc,
        mock_denied_proc,
        mock_no_such_proc,
        mock_partial_proc,
    ]

    with patch("psutil.process_iter", return_value=mock_procs):
        results = get_processes()

        # Should collect the valid proc and partial proc, skipping inaccessible ones
        assert len(results) == 2
        pids = [p["pid"] for p in results]
        assert 100 in pids
        assert 103 in pids

        partial_entry = next(p for p in results if p["pid"] == 103)
        assert partial_entry["exe"] is None
        assert partial_entry["username"] is None
        assert partial_entry["cmdline"] is None

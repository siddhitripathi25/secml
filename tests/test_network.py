"""Tests for network telemetry collector."""

from collections import namedtuple
import socket
from unittest.mock import patch
import psutil
from secml.collectors.network import get_network_connections

# Mock connection tuple matching psutil _sconn structure
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
MockAddr = namedtuple("MockAddr", ["ip", "port"])


def test_basic_structure():
    """Verify that get_network_connections normalizes connections into expected dictionary format."""
    mock_conns = [
        MockConn(
            fd=10,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=MockAddr(ip="192.168.1.10", port=443),
            raddr=MockAddr(ip="93.184.216.34", port=443),
            status="ESTABLISHED",
            pid=1234,
        ),
        MockConn(
            fd=11,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            laddr=("::1", 8080),
            raddr=("::1", 54321),
            status="ESTABLISHED",
            pid=5678,
        ),
    ]

    with patch("psutil.net_connections", return_value=mock_conns):
        results = get_network_connections()

        assert isinstance(results, list)
        assert len(results) == 2

        expected_keys = {
            "fd",
            "family",
            "type",
            "local_address",
            "remote_address",
            "status",
            "pid",
        }
        for res in results:
            assert expected_keys.issubset(res.keys())

        assert results[0]["local_address"] == "192.168.1.10:443"
        assert results[0]["remote_address"] == "93.184.216.34:443"
        assert results[0]["family"] == "AF_INET"
        assert results[0]["type"] == "SOCK_STREAM"
        assert results[0]["pid"] == 1234

        assert results[1]["local_address"] == "[::1]:8080"
        assert results[1]["remote_address"] == "[::1]:54321"
        assert results[1]["family"] == "AF_INET6"


def test_missing_remote_address():
    """Verify handling of connections with no remote endpoint (listening sockets)."""
    mock_conns = [
        MockConn(
            fd=5,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=MockAddr(ip="0.0.0.0", port=80),
            raddr=None,
            status="LISTEN",
            pid=800,
        )
    ]

    with patch("psutil.net_connections", return_value=mock_conns):
        results = get_network_connections()

        assert len(results) == 1
        assert results[0]["local_address"] == "0.0.0.0:80"
        assert results[0]["remote_address"] is None
        assert results[0]["status"] == "LISTEN"


def test_missing_pid():
    """Verify handling of connections where PID is None."""
    mock_conns = [
        MockConn(
            fd=None,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            laddr=MockAddr(ip="127.0.0.1", port=53),
            raddr=None,
            status="NONE",
            pid=None,
        )
    ]

    with patch("psutil.net_connections", return_value=mock_conns):
        results = get_network_connections()

        assert len(results) == 1
        assert results[0]["pid"] is None
        assert results[0]["local_address"] == "127.0.0.1:53"


def test_access_denied_handling():
    """Verify that psutil.AccessDenied returns an empty list instead of raising an error."""
    with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
        results = get_network_connections()
        assert results == []


def test_no_such_process_handling():
    """Verify that psutil.NoSuchProcess or OSError returns an empty list gracefully."""
    with patch("psutil.net_connections", side_effect=psutil.NoSuchProcess(pid=999)):
        results = get_network_connections()
        assert results == []

    with patch("psutil.net_connections", side_effect=PermissionError()):
        results = get_network_connections()
        assert results == []


def test_live_network_collection():
    """Verify that get_network_connections executes on the real system without errors."""
    results = get_network_connections()
    assert isinstance(results, list)

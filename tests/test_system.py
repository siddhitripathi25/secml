"""Tests for system information collector."""

from datetime import datetime
from secml.collectors.system import get_system_info


def test_get_system_info_structure():
    """Verify that get_system_info returns a dictionary with expected keys."""
    info = get_system_info()
    assert isinstance(info, dict)

    required_keys = {
        "platform",
        "os_release",
        "architecture",
        "cpu_count",
        "cpu_percent",
        "memory",
        "disk",
        "boot_time",
    }
    assert required_keys.issubset(info.keys())


def test_system_info_types_and_ranges():
    """Verify system info data types and sensible value ranges."""
    info = get_system_info()

    # OS details
    assert isinstance(info["platform"], str)
    assert isinstance(info["os_release"], str)
    assert isinstance(info["architecture"], str)

    # CPU details
    if info["cpu_count"] is not None:
        assert isinstance(info["cpu_count"], int)
        assert info["cpu_count"] > 0

    if info["cpu_percent"] is not None:
        assert isinstance(info["cpu_percent"], (int, float))
        assert 0.0 <= info["cpu_percent"] <= 100.0

    # Memory details
    memory = info["memory"]
    assert isinstance(memory, dict)
    assert "total" in memory and "available" in memory and "percent" in memory
    if memory["total"] is not None:
        assert isinstance(memory["total"], int)
        assert memory["total"] > 0
    if memory["available"] is not None:
        assert isinstance(memory["available"], int)
        assert memory["available"] >= 0
    if memory["percent"] is not None:
        assert isinstance(memory["percent"], (int, float))
        assert 0.0 <= memory["percent"] <= 100.0

    # Disk details
    disk = info["disk"]
    assert isinstance(disk, dict)
    assert "total" in disk and "free" in disk and "percent" in disk
    if disk["total"] is not None:
        assert isinstance(disk["total"], int)
        assert disk["total"] > 0
    if disk["free"] is not None:
        assert isinstance(disk["free"], int)
        assert disk["free"] >= 0
    if disk["percent"] is not None:
        assert isinstance(disk["percent"], (int, float))
        assert 0.0 <= disk["percent"] <= 100.0

    # Boot time
    if info["boot_time"] is not None:
        assert isinstance(info["boot_time"], str)
        parsed = datetime.fromisoformat(info["boot_time"])
        assert parsed is not None

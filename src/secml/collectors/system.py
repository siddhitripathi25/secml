"""System telemetry collector for SecML."""

from datetime import datetime, timezone
import os
import platform
from typing import Any, Dict, Optional
import psutil


def get_system_info() -> Dict[str, Any]:
    """Collect system telemetry metrics including OS, CPU, memory, disk, and boot time.

    Returns:
        Dict[str, Any]: Structured dictionary containing system info.
    """
    try:
        system_platform = platform.system()
        os_release = platform.release()
        architecture = platform.machine()
    except OSError:
        system_platform = "Unknown"
        os_release = "Unknown"
        architecture = "Unknown"

    try:
        cpu_count: Optional[int] = psutil.cpu_count()
    except (PermissionError, OSError):
        cpu_count = None

    try:
        cpu_percent: Optional[float] = psutil.cpu_percent(interval=0.1)
    except (PermissionError, OSError):
        cpu_percent = None

    try:
        vmem = psutil.virtual_memory()
        memory_info = {
            "total": vmem.total,
            "available": vmem.available,
            "percent": vmem.percent,
        }
    except (PermissionError, OSError):
        memory_info = {
            "total": None,
            "available": None,
            "percent": None,
        }

    root_path = os.path.abspath(os.sep)
    try:
        usage = psutil.disk_usage(root_path)
        disk_info = {
            "total": usage.total,
            "free": usage.free,
            "percent": usage.percent,
        }
    except (PermissionError, OSError, FileNotFoundError):
        disk_info = {
            "total": None,
            "free": None,
            "percent": None,
        }

    try:
        boot_timestamp = psutil.boot_time()
        boot_time_str: Optional[str] = datetime.fromtimestamp(
            boot_timestamp, tz=timezone.utc
        ).isoformat()
    except (PermissionError, OSError, ValueError, OverflowError):
        boot_time_str = None

    return {
        "platform": system_platform,
        "os_release": os_release,
        "architecture": architecture,
        "cpu_count": cpu_count,
        "cpu_percent": cpu_percent,
        "memory": memory_info,
        "disk": disk_info,
        "boot_time": boot_time_str,
    }

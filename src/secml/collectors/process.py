"""Process telemetry collector for SecML."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import psutil


def _clean_val(val: Any) -> Any:
    """Return None if value is a psutil exception indicator, else return value."""
    if isinstance(val, (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess)):
        return None
    return val


def get_processes() -> List[Dict[str, Any]]:
    """Collect telemetry metrics for currently running processes.

    Returns:
        List[Dict[str, Any]]: List of dictionaries containing process telemetry.
    """
    processes: List[Dict[str, Any]] = []

    attrs = [
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
    ]

    for proc in psutil.process_iter(attrs=attrs):
        try:
            pinfo = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except OSError:
            continue

        if not pinfo:
            continue

        pid = _clean_val(pinfo.get("pid"))
        if pid is None or not isinstance(pid, int):
            continue

        name = _clean_val(pinfo.get("name"))
        if name is not None and not isinstance(name, str):
            name = str(name)

        exe = _clean_val(pinfo.get("exe"))
        if exe is not None and not isinstance(exe, str):
            exe = str(exe)

        username = _clean_val(pinfo.get("username"))
        if username is not None and not isinstance(username, str):
            username = str(username)

        cpu_percent = _clean_val(pinfo.get("cpu_percent"))
        if cpu_percent is not None and not isinstance(cpu_percent, (int, float)):
            cpu_percent = None

        memory_percent = _clean_val(pinfo.get("memory_percent"))
        if memory_percent is not None and not isinstance(memory_percent, (int, float)):
            memory_percent = None

        status = _clean_val(pinfo.get("status"))
        if status is not None and not isinstance(status, str):
            status = str(status)

        num_threads = _clean_val(pinfo.get("num_threads"))
        if num_threads is not None and not isinstance(num_threads, int):
            num_threads = None

        cmdline_raw = _clean_val(pinfo.get("cmdline"))
        cmdline: Optional[List[str]] = None
        if isinstance(cmdline_raw, (list, tuple)):
            cmdline = [str(arg) for arg in cmdline_raw]

        create_time_raw = _clean_val(pinfo.get("create_time"))
        create_time_str: Optional[str] = None
        if isinstance(create_time_raw, (int, float)):
            try:
                create_time_str = datetime.fromtimestamp(
                    create_time_raw, tz=timezone.utc
                ).isoformat()
            except (ValueError, OverflowError, OSError):
                create_time_str = None

        processes.append(
            {
                "pid": pid,
                "name": name,
                "exe": exe,
                "username": username,
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "create_time": create_time_str,
                "status": status,
                "num_threads": num_threads,
                "cmdline": cmdline,
            }
        )

    return processes

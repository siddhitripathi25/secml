"""Rule-Based Detection Engine for SecML."""

from typing import Any, Dict, List, Optional

# Clear threshold constants for explainable rule-based detection
HIGH_CPU_THRESHOLD: float = 80.0  # Percentage
HIGH_MEMORY_THRESHOLD: float = 85.0  # Percentage
HIGH_NETWORK_CONNECTIONS_THRESHOLD: int = 50  # Active connection count
HIGH_THREAD_COUNT_THRESHOLD: int = 100  # Threads per process


def _check_cpu_rules(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate CPU-related rules."""
    detections: List[Dict[str, Any]] = []

    # Check top-level or system CPU percent
    cpu_percent = features.get("cpu_percent")
    if cpu_percent is None and isinstance(features.get("system"), dict):
        cpu_percent = features["system"].get("cpu_percent")

    if isinstance(cpu_percent, (int, float)) and cpu_percent >= HIGH_CPU_THRESHOLD:
        detections.append(
            {
                "rule_id": "HIGH_CPU_USAGE",
                "severity": "MEDIUM",
                "message": (
                    f"Potentially suspicious high system CPU usage detected "
                    f"({cpu_percent}% >= {HIGH_CPU_THRESHOLD}%)"
                ),
                "evidence": {
                    "cpu_percent": cpu_percent,
                },
            }
        )

    # Check per-process CPU percent
    processes = features.get("processes")
    if isinstance(processes, list):
        for proc in processes:
            if not isinstance(proc, dict):
                continue
            proc_cpu = proc.get("cpu_percent")
            if isinstance(proc_cpu, (int, float)) and proc_cpu >= HIGH_CPU_THRESHOLD:
                pid = proc.get("pid")
                proc_name = proc.get("name") or "unknown"
                detections.append(
                    {
                        "rule_id": "HIGH_CPU_USAGE",
                        "severity": "MEDIUM",
                        "message": (
                            f"Process '{proc_name}' (PID {pid}) is using potentially "
                            f"suspicious high CPU ({proc_cpu}% >= {HIGH_CPU_THRESHOLD}%)"
                        ),
                        "evidence": {
                            "cpu_percent": proc_cpu,
                            "pid": pid,
                            "process_name": proc_name,
                        },
                    }
                )

    return detections


def _check_memory_rules(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate memory-related rules."""
    detections: List[Dict[str, Any]] = []

    # Check system memory percent
    memory_percent = features.get("memory_percent")
    if memory_percent is None and isinstance(features.get("system"), dict):
        memory_percent = features["system"].get("memory_percent")

    if isinstance(memory_percent, (int, float)) and memory_percent >= HIGH_MEMORY_THRESHOLD:
        detections.append(
            {
                "rule_id": "HIGH_MEMORY_USAGE",
                "severity": "MEDIUM",
                "message": (
                    f"Potentially suspicious high system memory usage detected "
                    f"({memory_percent}% >= {HIGH_MEMORY_THRESHOLD}%)"
                ),
                "evidence": {
                    "memory_percent": memory_percent,
                },
            }
        )

    # Check process memory percent
    processes = features.get("processes")
    if isinstance(processes, list):
        for proc in processes:
            if not isinstance(proc, dict):
                continue
            proc_mem = proc.get("memory_percent")
            if isinstance(proc_mem, (int, float)) and proc_mem >= HIGH_MEMORY_THRESHOLD:
                pid = proc.get("pid")
                proc_name = proc.get("name") or "unknown"
                detections.append(
                    {
                        "rule_id": "HIGH_MEMORY_USAGE",
                        "severity": "MEDIUM",
                        "message": (
                            f"Process '{proc_name}' (PID {pid}) is using potentially "
                            f"suspicious high memory ({proc_mem}% >= {HIGH_MEMORY_THRESHOLD}%)"
                        ),
                        "evidence": {
                            "memory_percent": proc_mem,
                            "pid": pid,
                            "process_name": proc_name,
                        },
                    }
                )

    return detections


def _check_network_rules(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate network activity rules."""
    detections: List[Dict[str, Any]] = []

    # Check total network connections count
    total_conns = features.get("total_network_connections")
    net_data = features.get("network")

    if total_conns is None and isinstance(net_data, dict):
        total_conns = net_data.get("total_connections")

    if total_conns is None and isinstance(net_data, list):
        total_conns = len(net_data)

    if total_conns is None and isinstance(features.get("network_connections"), list):
        total_conns = len(features["network_connections"])

    if isinstance(total_conns, int) and total_conns >= HIGH_NETWORK_CONNECTIONS_THRESHOLD:
        detections.append(
            {
                "rule_id": "HIGH_NETWORK_ACTIVITY",
                "severity": "MEDIUM",
                "message": (
                    f"Potentially suspicious high network connection activity detected "
                    f"({total_conns} >= {HIGH_NETWORK_CONNECTIONS_THRESHOLD})"
                ),
                "evidence": {
                    "connection_count": total_conns,
                },
            }
        )

    return detections


def _check_process_rules(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate process-related suspicious behavior rules."""
    detections: List[Dict[str, Any]] = []

    processes = features.get("processes")
    if not isinstance(processes, list):
        return detections

    for proc in processes:
        if not isinstance(proc, dict):
            continue

        num_threads = proc.get("num_threads")
        pid = proc.get("pid")
        proc_name = proc.get("name") or "unknown"
        exe = proc.get("exe")

        # Check high thread count
        if isinstance(num_threads, int) and num_threads >= HIGH_THREAD_COUNT_THRESHOLD:
            detections.append(
                {
                    "rule_id": "SUSPICIOUS_PROCESS_BEHAVIOR",
                    "severity": "MEDIUM",
                    "message": (
                        f"Process '{proc_name}' (PID {pid}) has an unusually high thread count "
                        f"({num_threads} >= {HIGH_THREAD_COUNT_THRESHOLD})"
                    ),
                    "evidence": {
                        "pid": pid,
                        "process_name": proc_name,
                        "num_threads": num_threads,
                    },
                }
            )

        # Check suspicious execution path (e.g. executing from temporary directory)
        if isinstance(exe, str) and exe:
            exe_lower = exe.lower()
            suspicious_paths = ("/tmp/", "/var/tmp/", "/dev/shm/", "\\appdata\\local\\temp\\")
            if any(sp in exe_lower for sp in suspicious_paths):
                detections.append(
                    {
                        "rule_id": "SUSPICIOUS_PROCESS_BEHAVIOR",
                        "severity": "HIGH",
                        "message": (
                            f"Process '{proc_name}' (PID {pid}) is executing from a potentially "
                            f"suspicious temporary path ({exe})"
                        ),
                        "evidence": {
                            "pid": pid,
                            "process_name": proc_name,
                            "exe": exe,
                        },
                    }
                )

    return detections


def evaluate_rules(features: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluate predefined suspicious behavioral rules against extracted feature data.

    Args:
        features: Behavioral features dictionary.

    Returns:
        List[Dict[str, Any]]: List of triggered detection objects.
    """
    if not isinstance(features, dict):
        return []

    detections: List[Dict[str, Any]] = []

    detections.extend(_check_cpu_rules(features))
    detections.extend(_check_memory_rules(features))
    detections.extend(_check_network_rules(features))
    detections.extend(_check_process_rules(features))

    return detections

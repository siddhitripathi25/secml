"""Feature extraction module for SecML."""

from typing import Any, Dict, List, Optional
from secml.collectors.system import get_system_info
from secml.collectors.process import get_processes
from secml.collectors.network import get_network_connections


def extract_features(
    system_info: Optional[Dict[str, Any]] = None,
    processes: Optional[List[Dict[str, Any]]] = None,
    network_connections: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Extract and aggregate behavioral features from raw telemetry data.

    Args:
        system_info: Optional system telemetry dictionary.
        processes: Optional process telemetry list.
        network_connections: Optional network telemetry list.

    Returns:
        Dict[str, Any]: Structured behavioral features dictionary.
    """
    if system_info is None:
        system_info = get_system_info()
    if processes is None:
        processes = get_processes()
    if network_connections is None:
        network_connections = get_network_connections()

    # System features
    cpu_percent = system_info.get("cpu_percent") if isinstance(system_info, dict) else None
    mem_dict = system_info.get("memory") if isinstance(system_info, dict) and isinstance(system_info.get("memory"), dict) else {}
    memory_percent = mem_dict.get("percent")

    # Process features
    proc_list = processes if isinstance(processes, list) else []

    # Network features
    net_list = network_connections if isinstance(network_connections, list) else []
    total_connections = len(net_list)
    established_connections = sum(
        1 for conn in net_list if isinstance(conn, dict) and conn.get("status") == "ESTABLISHED"
    )

    return {
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "cpu_count": system_info.get("cpu_count") if isinstance(system_info, dict) else None,
            "platform": system_info.get("platform") if isinstance(system_info, dict) else None,
        },
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "processes": proc_list,
        "network": {
            "total_connections": total_connections,
            "established_connections": established_connections,
            "connections": net_list,
        },
        "total_network_connections": total_connections,
    }

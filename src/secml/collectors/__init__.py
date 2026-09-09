"""Data collectors module."""

from secml.collectors.network import collect_network_connections, get_network_connections
from secml.collectors.process import get_processes
from secml.collectors.system import get_system_info

__all__ = [
    "get_system_info",
    "get_processes",
    "get_network_connections",
    "collect_network_connections",
]



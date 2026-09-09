"""Network telemetry collector for SecML."""

import socket
from typing import Any, Dict, List, Optional
import psutil


def _format_address(addr: Any) -> Optional[str]:
    """Format socket address tuple or object into a string 'ip:port' or '[ip]:port'."""
    if not addr:
        return None
    try:
        if isinstance(addr, (tuple, list)) and len(addr) >= 2:
            ip, port = addr[0], addr[1]
            if ip is None or port is None:
                return None
            ip_str = str(ip)
            if ":" in ip_str:
                return f"[{ip_str}]:{port}"
            return f"{ip_str}:{port}"
        if hasattr(addr, "ip") and hasattr(addr, "port"):
            ip, port = getattr(addr, "ip"), getattr(addr, "port")
            if ip is None or port is None:
                return None
            ip_str = str(ip)
            if ":" in ip_str:
                return f"[{ip_str}]:{port}"
            return f"{ip_str}:{port}"
    except (AttributeError, IndexError, TypeError, ValueError):
        return None
    return None


def _format_family(family: Any) -> Optional[str]:
    """Format address family into a readable string."""
    if family is None:
        return None
    try:
        if isinstance(family, socket.AddressFamily):
            return family.name
        return socket.AddressFamily(family).name
    except (ValueError, TypeError, AttributeError):
        return str(family)


def _format_type(socket_type: Any) -> Optional[str]:
    """Format socket type into a readable string."""
    if socket_type is None:
        return None
    try:
        if isinstance(socket_type, socket.SocketKind):
            return socket_type.name
        return socket.SocketKind(socket_type).name
    except (ValueError, TypeError, AttributeError):
        return str(socket_type)


def get_network_connections() -> List[Dict[str, Any]]:
    """Collect currently active network connections using psutil.

    Returns:
        List[Dict[str, Any]]: List of normalized connection dictionaries.
    """
    connections: List[Dict[str, Any]] = []

    try:
        net_conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, OSError):
        return []

    for conn in net_conns:
        try:
            fd = getattr(conn, "fd", None)
            if fd is not None and not isinstance(fd, int):
                fd = None

            family = _format_family(getattr(conn, "family", None))
            sock_type = _format_type(getattr(conn, "type", None))
            laddr = _format_address(getattr(conn, "laddr", None))
            raddr = _format_address(getattr(conn, "raddr", None))

            status = getattr(conn, "status", None)
            if status is not None and not isinstance(status, str):
                status = str(status)

            pid = getattr(conn, "pid", None)
            if pid is not None and not isinstance(pid, int):
                pid = None

            connections.append(
                {
                    "fd": fd,
                    "family": family,
                    "type": sock_type,
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": status,
                    "pid": pid,
                }
            )
        except (AttributeError, ValueError, TypeError):
            continue

    return connections


collect_network_connections = get_network_connections

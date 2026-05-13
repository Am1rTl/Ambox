import socket
import time
from typing import Any

from app.config_parser import Profile


def _extract_endpoint(outbound: dict[str, Any]) -> tuple[str, int] | None:
    server = outbound.get("server")
    port = outbound.get("server_port") or outbound.get("port")

    if isinstance(server, str) and not port and ":" in server:
        host, _, raw_port = server.rpartition(":")
        if host and raw_port.isdigit():
            server = host
            port = int(raw_port)

    if not isinstance(server, str) or not server:
        return None

    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return None

    if port_num <= 0 or port_num > 65535:
        return None

    return server, port_num


def profile_latency_ms(profile: Profile, timeout_sec: float) -> int | None:
    endpoint = _extract_endpoint(profile.outbound)
    if endpoint is None:
        return None

    started = time.perf_counter()
    try:
        sock = socket.create_connection(endpoint, timeout=timeout_sec)
        sock.close()
    except OSError:
        return None

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return max(1, elapsed_ms)

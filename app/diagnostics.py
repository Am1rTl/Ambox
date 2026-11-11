"""On-demand connection diagnostics. Never open an external URL when VPN is down."""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Any


def process_memory_bytes(pid: int) -> int | None:
    try:
        for line in (Path('/proc') / str(pid) / 'status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def connected_diagnostics(*, connected: bool, interface: str,
                          process_pid: int | None = None) -> dict[str, Any]:
    """Network requests are permitted ONLY if a tunnel is visibly present."""
    from app.net_session import interface_exists
    from app.latency import probe_active_connection

    result: dict[str, Any] = {'checked_at': time.time(), 'vpn_running': bool(connected),
                              'interface': interface, 'interface_up': interface_exists(interface),
                              'external_ip': None, 'country': None,
                              'latency_ms': None, 'dns_ok': None,
                              'process_memory_bytes': process_memory_bytes(process_pid) if process_pid else None}
    if not (connected and result['interface_up']):
        result['message'] = 'VPN is disconnected or TUN interface is missing; no network probe was sent.'
        return result
    # DNS check and HTTP RTT are tunnel-level probes, unlike endpoint ping.
    try:
        result['dns_ok'] = bool(socket.getaddrinfo('example.com', 443, type=socket.SOCK_STREAM))
    except OSError:
        result['dns_ok'] = False
    probe = probe_active_connection(timeout_sec=4.0)
    if probe and probe.get('ok'):
        result['external_ip'] = probe.get('ip')
        result['country'] = probe.get('loc')
        result['latency_ms'] = probe.get('latency_ms')
        result['message'] = 'External probe succeeded; split routes may bypass the VPN.'
    else:
        result['message'] = 'End-to-end probe failed. Check DNS, firewall and VPN logs.'
    return result

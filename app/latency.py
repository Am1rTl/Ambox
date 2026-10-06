from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from typing import Any
from urllib.request import Request, urlopen

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


def profile_latency_ms(profile: Profile, timeout_sec: float = 2.5) -> int | None:
    singbox = shutil.which("sing-box")
    if not singbox:
        for candidate in (
            "/usr/bin/sing-box",
            "/usr/local/bin/sing-box",
        ):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                singbox = candidate
                break

    if singbox and os.access(singbox, os.X_OK):
        start = time.perf_counter()
        cfg = {"outbounds": [profile.outbound]}
        tag = str(profile.outbound.get("tag") or "proxy")
        try:
            res = subprocess.run(
                [
                    singbox,
                    "tools",
                    "fetch",
                    "https://cloudflare.com/cdn-cgi/trace",
                    "-c",
                    "/dev/stdin",
                    "-o",
                    tag,
                ],
                input=json.dumps(cfg),
                text=True,
                capture_output=True,
                timeout=timeout_sec,
            )
            elapsed = int((time.perf_counter() - start) * 1000)
            if res.returncode == 0:
                return max(1, elapsed)
            return None
        except Exception:
            return None

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


def probe_active_connection(
    probe_url: str = "https://cloudflare.com/cdn-cgi/trace",
    timeout_sec: float = 4.0,
) -> dict[str, Any] | None:
    """
    Sends an HTTP probe through the active network/TUN to wake up and verify end-to-end traffic.
    Matches the Happ observatory probe logic.
    """
    start = time.perf_counter()
    req = Request(
        probe_url,
        headers={"User-Agent": "Ambox/1.0 Happ/1.0", "Accept": "*/*"},
    )
    try:
        with urlopen(req, timeout=timeout_sec) as resp:
            data = resp.read(4096).decode("utf-8", errors="replace")
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            parsed: dict[str, Any] = {"ok": True, "latency_ms": elapsed_ms}
            for line in data.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    parsed[k.strip().lower()] = v.strip()
            return parsed
    except Exception:
        # Fallback to generate_204
        fallback_start = time.perf_counter()
        try:
            req_fb = Request(
                "http://cp.cloudflare.com/generate_204",
                headers={"User-Agent": "Ambox/1.0", "Accept": "*/*"},
            )
            with urlopen(req_fb, timeout=timeout_sec) as resp:
                elapsed_ms = int((time.perf_counter() - fallback_start) * 1000)
                return {"ok": True, "latency_ms": elapsed_ms}
        except Exception:
            return None

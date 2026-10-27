from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.request import Request, urlopen

from app.config_parser import Profile, convert_bundle_outbound, normalize_outbound
from app.xray_bundle import bundle_proxy_outbounds


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


def _find_singbox() -> str | None:
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
        return singbox
    return None


def outbound_latency_ms(outbound: dict[str, Any], timeout_sec: float = 2.5) -> int | None:
    singbox = _find_singbox()
    if singbox:
        outbound = normalize_outbound(outbound)
        tag = str(outbound.get("tag") or "proxy")
        # auto_detect_interface binds the probe to the physical interface, so while the VPN is up
        # servers are measured directly instead of through the active tunnel.
        cfg = {"outbounds": [outbound], "route": {"auto_detect_interface": True}}
        start = time.perf_counter()
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

    endpoint = _extract_endpoint(outbound)
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


def _backup_candidates(profile: Profile, limit: int) -> list[dict[str, Any]]:
    seen = {(profile.outbound.get("server"), profile.outbound.get("server_port"))}
    result = []
    for _, outbound in bundle_proxy_outbounds(profile.xray or {}, convert_bundle_outbound):
        key = (outbound.get("server"), outbound.get("server_port"))
        if key in seen:
            continue
        seen.add(key)
        result.append(outbound)
        if len(result) >= limit:
            break
    return result


def profile_latency_ms(profile: Profile, timeout_sec: float = 2.5) -> int | None:
    latency = outbound_latency_ms(profile.outbound, timeout_sec)
    if latency is not None or not profile.xray:
        return latency
    # Happ configs fail over to their other nodes when the default one is blocked, so the
    # profile is usable as long as some of them answer.
    backups = _backup_candidates(profile, limit=3)
    if not backups:
        return None
    with ThreadPoolExecutor(max_workers=len(backups)) as executor:
        results = [r for r in executor.map(lambda ob: outbound_latency_ms(ob, timeout_sec), backups) if r is not None]
    return min(results) if results else None


def find_unavailable_nodes(xray: dict[str, Any], timeout_sec: float = 4.0) -> set[str]:
    """Xray tags of the config's nodes that do not answer from the current network."""
    nodes = bundle_proxy_outbounds(xray, convert_bundle_outbound)
    if not nodes:
        return set()
    # Configs repeat the same node under several tags; probe each distinct node once.
    by_node: dict[str, list[str]] = {}
    probes: dict[str, dict[str, Any]] = {}
    for xtag, outbound in nodes:
        key = json.dumps({k: v for k, v in outbound.items() if k != "tag"}, sort_keys=True)
        by_node.setdefault(key, []).append(xtag)
        probes.setdefault(key, outbound)
    keys = list(probes)
    with ThreadPoolExecutor(max_workers=min(32, len(keys))) as executor:
        results = list(executor.map(lambda k: outbound_latency_ms(probes[k], timeout_sec), keys))
    dead: set[str] = set()
    for key, latency in zip(keys, results):
        if latency is None:
            dead.update(by_node[key])
    return dead


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

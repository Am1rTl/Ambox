"""
Full Xray/Happ config support ("Happ proxy" mode).

Happ-style subscriptions (e.g. HiroVPN) ship one complete Xray config per server: several proxy
outbounds, balancers over them and routing rules that pick an outbound per domain / IP / port.
Using only the first outbound breaks such servers (non-standard ports, YouTube, AI services and
blocked IPs are meant to go through other nodes), so this module converts the whole config into
sing-box outbounds, urltest groups and route rules.

geosite:/geoip: references are served from MetaCubeX sing-box rule-sets, downloaded once and cached
locally so that sing-box never has to fetch anything while the TUN is coming up.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.app_paths import ensure_user_owned, rule_sets_dir

RULE_SET_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/{kind}/{name}.srs"
RULE_SET_MAX_AGE_SECONDS = 7 * 24 * 3600
RULE_SET_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_PROBE_URL = "https://www.gstatic.com/generate_204"
URLTEST_INTERVAL = "3m"
XRAY_KEYS = ("outbounds", "routing", "observatory", "burstObservatory")

_DIRECT = "direct"
_REJECT = "__reject__"
_DNS = "__dns__"
_UNAVAILABLE = "__unavailable__"
_RESERVED_TAGS = {"direct", "block", "proxy", "tun-in", "dns-out"}


@dataclass
class SingboxBundle:
    outbounds: list[dict[str, Any]] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    rule_sets: dict[str, tuple[str, str]] = field(default_factory=dict)
    main_tag: str = ""
    final_tag: str = ""
    # True when the config's own default node was unavailable and a backup group took over.
    using_backup: bool = False


def is_xray_bundle(item: dict[str, Any]) -> bool:
    """A full Xray config worth keeping as a whole: has routing or more than one proxy outbound."""
    outbounds = item.get("outbounds")
    if not isinstance(outbounds, list):
        return False
    if not any(isinstance(ob, dict) and "protocol" in ob for ob in outbounds):
        return False
    routing = item.get("routing")
    if isinstance(routing, dict) and (routing.get("rules") or routing.get("balancers")):
        return True
    proxies = [
        ob
        for ob in outbounds
        if isinstance(ob, dict) and str(ob.get("protocol") or "").lower() not in {"freedom", "blackhole", "dns"}
    ]
    return len(proxies) > 1


def extract_xray_bundle(item: dict[str, Any]) -> dict[str, Any]:
    return {key: item[key] for key in XRAY_KEYS if key in item}


def rule_set_tag(kind: str, name: str) -> str:
    return f"{kind}-{name}"


def _split_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).split(",") if x.strip()]


def _convert_ports(value: Any) -> tuple[list[int], list[str]]:
    ports: list[int] = []
    ranges: list[str] = []
    for part in _split_list(value):
        if "-" in part:
            start, _, end = part.partition("-")
            if start.strip().isdigit() and end.strip().isdigit():
                ranges.append(f"{int(start)}:{int(end)}")
        elif part.isdigit():
            ports.append(int(part))
    return ports, ranges


def _convert_cidr(value: str) -> str | None:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


class _RuleConverter:
    def __init__(self, rule_set_available: Callable[[str, str], bool]) -> None:
        self._available = rule_set_available
        self.used_rule_sets: dict[str, tuple[str, str]] = {}

    def _geo(self, kind: str, name: str) -> str | None:
        name = name.strip().lower().split("@", 1)[0]
        if not name or name.startswith("!"):
            return None
        if not self._available(kind, name):
            return None
        tag = rule_set_tag(kind, name)
        self.used_rule_sets[tag] = (kind, name)
        return tag

    def domain_match(self, values: list[str]) -> dict[str, Any] | None:
        out: dict[str, list[Any]] = {}
        for raw in values:
            prefix, sep, rest = raw.partition(":")
            if not sep:
                prefix, rest = "keyword", raw
            prefix = prefix.lower()
            rest = rest.strip()
            if not rest:
                continue
            if prefix == "domain":
                out.setdefault("domain_suffix", []).append(rest.lower())
            elif prefix == "full":
                out.setdefault("domain", []).append(rest.lower())
            elif prefix == "keyword":
                out.setdefault("domain_keyword", []).append(rest.lower())
            elif prefix == "regexp":
                out.setdefault("domain_regex", []).append(rest)
            elif prefix == "geosite":
                tag = self._geo("geosite", rest)
                if tag:
                    out.setdefault("rule_set", []).append(tag)
            # ext:file.dat:tag and other custom matchers cannot be reproduced; skip them.
        return out or None

    def ip_match(self, values: list[str]) -> dict[str, Any] | None:
        out: dict[str, Any] = {}
        for raw in values:
            if raw.lower().startswith("geoip:"):
                name = raw[6:].strip().lower()
                if name == "private":
                    out["ip_is_private"] = True
                    continue
                tag = self._geo("geoip", name)
                if tag:
                    out.setdefault("rule_set", []).append(tag)
                continue
            cidr = _convert_cidr(raw)
            if cidr:
                out.setdefault("ip_cidr", []).append(cidr)
        return out or None

    def convert(self, rule: dict[str, Any], target: dict[str, Any]) -> dict[str, Any] | None:
        # Rules bound to Xray's own inbounds / users can never match traffic from our TUN.
        if rule.get("inboundTag") or rule.get("user") or rule.get("attrs"):
            return None

        common: dict[str, Any] = {}
        network = [n.lower() for n in _split_list(rule.get("network")) if n.lower() in {"tcp", "udp"}]
        if network and set(network) != {"tcp", "udp"}:
            common["network"] = network
        if rule.get("port") not in (None, ""):
            ports, ranges = _convert_ports(rule.get("port"))
            if not ports and not ranges:
                return None
            if ports:
                common["port"] = ports
            if ranges:
                common["port_range"] = ranges
        if rule.get("sourcePort") not in (None, ""):
            ports, ranges = _convert_ports(rule.get("sourcePort"))
            if ports:
                common["source_port"] = ports
            if ranges:
                common["source_port_range"] = ranges
        if rule.get("source"):
            sources = [c for c in (_convert_cidr(x) for x in _split_list(rule.get("source"))) if c]
            if not sources:
                return None
            common["source_ip_cidr"] = sources
        protocols = [p.lower() for p in _split_list(rule.get("protocol"))]
        if protocols:
            common["protocol"] = protocols

        domains = _split_list(rule.get("domain") or rule.get("domains"))
        ips = _split_list(rule.get("ip"))
        domain_match = self.domain_match(domains) if domains else None
        ip_match = self.ip_match(ips) if ips else None
        # A rule whose every domain/IP matcher is unavailable must be dropped: keeping it without
        # those conditions would turn it into a catch-all.
        if (domains and domain_match is None) or (ips and ip_match is None):
            return None

        if domain_match and ip_match:
            # sing-box ORs domain and IP fields inside one rule, Xray ANDs them.
            return {
                "type": "logical",
                "mode": "and",
                "rules": [{**common, **domain_match}, ip_match],
                **target,
            }
        return {**common, **(domain_match or {}), **(ip_match or {}), **target}


def _is_ip_rule(rule: dict[str, Any]) -> bool:
    if rule.get("type") == "logical":
        return True
    return bool(rule.get("ip_cidr") or rule.get("ip_is_private") or any(t.startswith("geoip-") for t in rule.get("rule_set", [])))


def bundle_proxy_outbounds(
    xray: dict[str, Any], convert_outbound: Callable[[dict[str, Any]], dict[str, Any] | None]
) -> list[tuple[str, dict[str, Any]]]:
    """(xray tag, sing-box outbound) for every proxy node sing-box can run, in config order."""
    result = []
    for i, ob in enumerate(xray.get("outbounds") or []):
        if not isinstance(ob, dict) or str(ob.get("protocol") or "").lower() in {"freedom", "blackhole", "dns"}:
            continue
        converted = convert_outbound(ob)
        if converted:
            result.append((str(ob.get("tag") or f"xray-out-{i}"), converted))
    return result


def convert_xray_bundle(
    xray: dict[str, Any],
    convert_outbound: Callable[[dict[str, Any]], dict[str, Any] | None],
    rule_set_available: Callable[[str, str], bool],
    unavailable: set[str] | frozenset[str] = frozenset(),
) -> SingboxBundle:
    """
    `unavailable` holds Xray tags of nodes that failed a reachability probe. They are left out;
    whatever pointed at them (the default node, balancers, per-service rules) is served by a
    backup urltest group over the remaining nodes of the same config.
    """
    raw_outbounds = [ob for ob in (xray.get("outbounds") or []) if isinstance(ob, dict)]
    routing = xray.get("routing") if isinstance(xray.get("routing"), dict) else {}
    observatory = xray.get("observatory") or xray.get("burstObservatory") or {}
    probe_url = DEFAULT_PROBE_URL
    if isinstance(observatory, dict):
        probe_url = str(observatory.get("probeURL") or observatory.get("pingConfig", {}).get("destination") or probe_url)

    bundle = SingboxBundle()
    used_tags: set[str] = set(_RESERVED_TAGS)
    tag_map: dict[str, str] = {}
    proxy_order: list[tuple[str, str]] = []  # (xray tag, sing-box tag)
    default_tag: str | None = None

    def unique(tag: str) -> str:
        candidate = tag
        n = 2
        while candidate in used_tags:
            candidate = f"{tag}-{n}"
            n += 1
        used_tags.add(candidate)
        return candidate

    for i, ob in enumerate(raw_outbounds):
        xtag = str(ob.get("tag") or f"xray-out-{i}")
        proto = str(ob.get("protocol") or "").lower()
        if proto == "freedom":
            mapped = _DIRECT
        elif proto == "blackhole":
            mapped = _REJECT
        elif proto == "dns":
            mapped = _DNS
        else:
            converted = convert_outbound(ob)
            if not converted:
                logging.info("Happ config: skipping unsupported outbound %s (%s)", xtag, proto)
                continue
            if xtag in unavailable:
                if default_tag is None:
                    default_tag = _UNAVAILABLE
                continue
            mapped = unique(xtag)
            converted["tag"] = mapped
            bundle.outbounds.append(converted)
            proxy_order.append((xtag, mapped))
        tag_map.setdefault(xtag, mapped)
        if default_tag is None:
            default_tag = mapped

    if not proxy_order:
        raise ValueError("config has no reachable outbounds supported by sing-box")
    bundle.using_backup = default_tag == _UNAVAILABLE
    first_proxy = proxy_order[0][1]
    backup_tag: str | None = None

    def backup() -> str:
        nonlocal backup_tag
        if backup_tag is None:
            if len(proxy_order) == 1:
                backup_tag = first_proxy
            else:
                backup_tag = unique("auto")
                bundle.outbounds.append(
                    {
                        "type": "urltest",
                        "tag": backup_tag,
                        "outbounds": [tag for _, tag in proxy_order],
                        "url": probe_url,
                        "interval": URLTEST_INTERVAL,
                        "tolerance": 50,
                    }
                )
        return backup_tag

    balancer_map: dict[str, str] = {}
    for bal in routing.get("balancers") or []:
        if not isinstance(bal, dict) or not bal.get("tag"):
            continue
        selectors = _split_list(bal.get("selector"))
        members = [tag for xtag, tag in proxy_order if any(xtag.startswith(sel) for sel in selectors)]
        fallback = tag_map.get(str(bal.get("fallbackTag") or ""))
        if fallback and fallback not in {_DIRECT, _REJECT, _DNS} and fallback not in members:
            members.append(fallback)
        if not members:
            balancer_map[bal["tag"]] = fallback or backup()
        elif len(members) == 1:
            balancer_map[bal["tag"]] = members[0]
        else:
            group_tag = unique(str(bal["tag"]))
            bundle.outbounds.append(
                {
                    "type": "urltest",
                    "tag": group_tag,
                    "outbounds": members,
                    "url": probe_url,
                    "interval": URLTEST_INTERVAL,
                    "tolerance": 50,
                }
            )
            balancer_map[bal["tag"]] = group_tag

    # Prefer a group containing the default node so that a dead node fails over.
    bundle.main_tag = backup() if bundle.using_backup else first_proxy
    for ob in bundle.outbounds:
        if not bundle.using_backup and ob.get("type") == "urltest" and first_proxy in ob["outbounds"]:
            bundle.main_tag = ob["tag"]
            break
    bundle.final_tag = default_tag if default_tag == _DIRECT else bundle.main_tag

    converter = _RuleConverter(rule_set_available)
    resolve_ips = str(routing.get("domainStrategy") or "AsIs").lower() in {"ipifnonmatch", "ipondemand"}
    resolve_added = False
    for rule in routing.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        if rule.get("balancerTag"):
            target_tag = balancer_map.get(str(rule["balancerTag"]), bundle.main_tag)
        elif rule.get("outboundTag"):
            target_tag = tag_map.get(str(rule["outboundTag"])) or backup()
        else:
            continue
        if target_tag == _REJECT:
            target: dict[str, Any] = {"action": "reject"}
        elif target_tag == _DNS:
            target = {"action": "hijack-dns"}
        else:
            target = {"outbound": target_tag}
        converted = converter.convert(rule, target)
        if converted is None:
            continue
        if not set(converted) - {"outbound", "action"}:
            # Unconditional rule: everything after it is unreachable, so it is the real default.
            if "outbound" in converted:
                bundle.final_tag = converted["outbound"]
                break
            bundle.rules.append({"network": ["tcp", "udp"], "action": converted["action"]})
            break
        if resolve_ips and not resolve_added and _is_ip_rule(converted):
            bundle.rules.append({"action": "resolve", "strategy": "prefer_ipv4"})
            resolve_added = True
        bundle.rules.append(converted)

    bundle.rule_sets = converter.used_rule_sets
    return bundle


def required_rule_sets(xray: dict[str, Any]) -> set[tuple[str, str]]:
    names: set[tuple[str, str]] = set()
    routing = xray.get("routing") if isinstance(xray.get("routing"), dict) else {}
    for rule in routing.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        for raw in _split_list(rule.get("domain") or rule.get("domains")):
            if raw.lower().startswith("geosite:"):
                name = raw[8:].strip().lower().split("@", 1)[0]
                if name and not name.startswith("!"):
                    names.add(("geosite", name))
        for raw in _split_list(rule.get("ip")):
            if raw.lower().startswith("geoip:"):
                name = raw[6:].strip().lower()
                if name and name != "private" and not name.startswith("!"):
                    names.add(("geoip", name))
    return names


def rule_set_path(kind: str, name: str) -> Path:
    safe = name.replace("/", "_")
    return rule_sets_dir() / f"{kind}-{safe}.srs"


def _download_rule_set(kind: str, name: str, timeout: float) -> bool:
    path = rule_set_path(kind, name)
    url = RULE_SET_URL.format(kind=kind, name=quote(name, safe="!-_."))
    try:
        with urlopen(Request(url, headers={"User-Agent": "ambox/1.0"}), timeout=timeout) as response:
            data = response.read(RULE_SET_MAX_BYTES + 1)
    except Exception as exc:
        logging.warning("Failed to download rule-set %s:%s: %s", kind, name, exc)
        return False
    if not data or len(data) > RULE_SET_MAX_BYTES:
        return False
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_bytes(data)
        ensure_user_owned(tmp)
        os.replace(tmp, path)
    except OSError as exc:
        logging.warning("Failed to store rule-set %s: %s", path, exc)
        return False
    return True


def ensure_rule_sets(names: set[tuple[str, str]], timeout: float = 8.0) -> None:
    """Download missing or stale rule-sets. A stale file is still used if refreshing fails."""
    now = time.time()
    todo = []
    for kind, name in names:
        path = rule_set_path(kind, name)
        try:
            fresh = now - path.stat().st_mtime < RULE_SET_MAX_AGE_SECONDS
        except OSError:
            fresh = False
        if not fresh:
            todo.append((kind, name))
    if not todo:
        return
    with ThreadPoolExecutor(max_workers=min(8, len(todo))) as executor:
        list(executor.map(lambda item: _download_rule_set(item[0], item[1], timeout), todo))


def cached_rule_set_available(kind: str, name: str) -> bool:
    return rule_set_path(kind, name).is_file()

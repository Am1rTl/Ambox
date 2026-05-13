import base64
import binascii
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from app.app_paths import singbox_cache_path


@dataclass
class Profile:
    name: str
    outbound: dict[str, Any]


@dataclass
class RoutingOptions:
    mode: str = "all"
    include_subdomains: bool = True
    dns_mode: str = "proxy"
    custom_dns: str = ""
    domains: list[str] = field(default_factory=list)


class ConfigError(Exception):
    pass


def _decode_base64_text(payload: str, context: str) -> str:
    value = payload.strip()
    if not value:
        raise ConfigError(f"{context}: empty payload")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ConfigError(f"{context}: invalid base64 payload") from exc


def _supports_udp(outbound: dict[str, Any]) -> bool:
    """
    Best-effort check: for TCP-only VLESS/VMess/Trojan links, sing-box cannot proxy UDP
    unless packet encoding is explicitly enabled.
    """
    out_type = str(outbound.get("type", "")).lower()
    network = str(outbound.get("network", "")).lower()
    packet_encoding = str(outbound.get("packet_encoding", "")).lower()
    transport_type = str((outbound.get("transport") or {}).get("type", "")).lower()

    if out_type in {"vless", "vmess", "trojan"}:
        if packet_encoding in {"xudp", "packetaddr"}:
            return True
        if network == "udp" or transport_type == "quic":
            return True
        return False

    return True


def normalize_domain(value: str) -> str | None:
    raw = value.strip().lower()
    if not raw:
        return None
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    if raw.startswith("*."):
        raw = raw[2:]
    raw = raw.strip(".")
    if not raw or "/" in raw or " " in raw:
        return None
    return raw


def parse_domains_text(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        candidate = normalize_domain(line)
        if not candidate:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def _build_transport_from_link(
    transport_type: str, query: dict[str, list[str]], default_path: str = "", default_host: str = ""
) -> dict[str, Any] | None:
    t = (transport_type or "tcp").lower()
    if t in {"tcp", "raw", ""}:
        return None

    if t not in {"ws", "grpc", "http", "httpupgrade", "quic"}:
        raise ConfigError(f"unsupported transport type: {t}")

    transport: dict[str, Any] = {"type": t}
    path = query.get("path", [default_path])[0]
    host = query.get("host", [default_host])[0]
    service_name = query.get("serviceName", [""])[0] or query.get("service_name", [""])[0]

    if t in {"ws", "http", "httpupgrade"}:
        if path:
            transport["path"] = unquote(path)
        if host:
            transport["headers"] = {"Host": host}
    elif t == "grpc":
        if service_name:
            transport["service_name"] = service_name

    return transport


def _build_tls_from_link(query: dict[str, list[str]], server: str, security: str) -> dict[str, Any] | None:
    sec = security.lower()
    if sec not in {"tls", "reality"}:
        return None

    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": query.get("sni", [server])[0],
    }
    if query.get("allowInsecure", ["0"])[0] == "1":
        tls["insecure"] = True

    fingerprint = query.get("fp", [""])[0] or query.get("fingerprint", [""])[0]
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    if sec == "reality":
        public_key = query.get("pbk", [""])[0] or query.get("publicKey", [""])[0]
        short_id = query.get("sid", [""])[0] or query.get("shortId", [""])[0]
        if not public_key:
            raise ConfigError("vless reality: missing pbk/publicKey")
        tls["reality"] = {"enabled": True, "public_key": public_key}
        if short_id:
            tls["reality"]["short_id"] = short_id

    return tls


def _decode_vmess(uri: str) -> Profile:
    payload = uri.removeprefix("vmess://").strip()
    raw = _decode_base64_text(payload, "vmess")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError("vmess: invalid json payload") from exc
    if not isinstance(data, dict):
        raise ConfigError("vmess: payload must be a JSON object")

    server = data.get("add")
    uuid = data.get("id")
    if not server or not uuid:
        raise ConfigError("vmess: missing add/id")
    try:
        port = int(data.get("port", 443))
    except (TypeError, ValueError) as exc:
        raise ConfigError("vmess: invalid port") from exc

    outbound: dict[str, Any] = {
        "type": "vmess",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": "auto",
        "alter_id": 0,
        "network": "tcp",
    }
    try:
        outbound["alter_id"] = int(data.get("aid", 0))
    except (TypeError, ValueError) as exc:
        raise ConfigError("vmess: invalid aid") from exc

    net = (data.get("net") or "tcp").lower()
    transport = _build_transport_from_link(
        net,
        {},
        default_path=data.get("path") or "",
        default_host=data.get("host") or "",
    )
    if transport:
        outbound["transport"] = transport

    if data.get("tls") == "tls":
        outbound["tls"] = {"enabled": True, "server_name": data.get("sni") or server}

    return Profile(name=data.get("ps") or f"vmess-{server}", outbound=outbound)


def _decode_vless(uri: str) -> Profile:
    parsed = urlparse(uri)
    uuid = parsed.username
    server = parsed.hostname
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ConfigError("vless: invalid port") from exc
    if not uuid or not server:
        raise ConfigError("vless: missing uuid/server")

    query = parse_qs(parsed.query)
    transport_type = query.get("type", ["tcp"])[0]
    security = query.get("security", ["none"])[0]
    name = unquote(parsed.fragment) if parsed.fragment else f"vless-{server}"

    outbound: dict[str, Any] = {
        "type": "vless",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "uuid": uuid,
        "network": "tcp",
    }
    flow = query.get("flow", [""])[0]
    if flow:
        outbound["flow"] = flow

    transport = _build_transport_from_link(transport_type, query)
    if transport:
        outbound["transport"] = transport

    tls = _build_tls_from_link(query, server, security)
    if tls:
        outbound["tls"] = tls

    return Profile(name=name, outbound=outbound)


def _decode_trojan(uri: str) -> Profile:
    parsed = urlparse(uri)
    password = parsed.username
    server = parsed.hostname
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ConfigError("trojan: invalid port") from exc
    if not password or not server:
        raise ConfigError("trojan: missing password/server")

    query = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else f"trojan-{server}"
    outbound: dict[str, Any] = {
        "type": "trojan",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "password": password,
        "network": "tcp",
    }

    security = query.get("security", ["tls"])[0]
    tls = _build_tls_from_link(query, server, security)
    if tls:
        outbound["tls"] = tls

    transport = _build_transport_from_link(query.get("type", ["tcp"])[0], query)
    if transport:
        outbound["transport"] = transport

    return Profile(name=name, outbound=outbound)


def _decode_ss(uri: str) -> Profile:
    raw = uri.removeprefix("ss://")
    name = ""
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        name = unquote(fragment)
    raw = raw.strip()
    if not raw:
        raise ConfigError("ss: empty payload")

    parsed = urlparse(f"ss://{raw}")
    method = ""
    password = ""
    server = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("ss: invalid port") from exc

    if server and port is not None:
        if parsed.password is None:
            encoded_userinfo = parsed.username or ""
            userinfo = unquote(encoded_userinfo)
            if ":" not in userinfo:
                userinfo = _decode_base64_text(userinfo, "ss userinfo")
            if ":" not in userinfo:
                raise ConfigError("ss: invalid credentials format")
            method, password = userinfo.split(":", 1)
        else:
            method = unquote(parsed.username or "")
            password = unquote(parsed.password)
    else:
        encoded = raw.split("?", 1)[0].split("/", 1)[0]
        decoded = _decode_base64_text(encoded, "ss")
        if "@" not in decoded:
            raise ConfigError("ss: invalid legacy payload")
        creds, endpoint = decoded.split("@", 1)
        if ":" not in creds:
            raise ConfigError("ss: invalid legacy credentials")
        method, password = creds.split(":", 1)
        endpoint_server, sep, endpoint_port = endpoint.rpartition(":")
        if not sep or not endpoint_server:
            raise ConfigError("ss: invalid legacy endpoint")
        server = endpoint_server
        try:
            port = int(endpoint_port)
        except ValueError as exc:
            raise ConfigError("ss: invalid legacy port") from exc

    if not method or not password or not server or port is None:
        raise ConfigError("ss: incomplete profile")

    outbound = {
        "type": "shadowsocks",
        "tag": "proxy",
        "method": method,
        "password": password,
        "server": server,
        "server_port": int(port),
    }
    return Profile(name=name or f"ss-{server}", outbound=outbound)


def _decode_http_proxy(uri: str) -> Profile:
    parsed = urlparse(uri)
    server = parsed.hostname
    if not server:
        raise ConfigError("http proxy: missing server")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ConfigError("http proxy: invalid port") from exc

    outbound: dict[str, Any] = {
        "type": "http",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
    }
    if parsed.username:
        outbound["username"] = unquote(parsed.username)
    if parsed.password:
        outbound["password"] = unquote(parsed.password)
    if parsed.scheme.lower() == "https":
        outbound["tls"] = {"enabled": True, "server_name": server}

    name = unquote(parsed.fragment) if parsed.fragment else f"http-{server}"
    return Profile(name=name, outbound=outbound)


def _decode_socks_proxy(uri: str) -> Profile:
    parsed = urlparse(uri)
    server = parsed.hostname
    if not server:
        raise ConfigError("socks proxy: missing server")
    try:
        port = parsed.port or 1080
    except ValueError as exc:
        raise ConfigError("socks proxy: invalid port") from exc

    outbound: dict[str, Any] = {
        "type": "socks",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "version": "5",
    }
    if parsed.username:
        outbound["username"] = unquote(parsed.username)
    if parsed.password:
        outbound["password"] = unquote(parsed.password)

    name = unquote(parsed.fragment) if parsed.fragment else f"socks-{server}"
    return Profile(name=name, outbound=outbound)


def parse_uri_line(line: str) -> Profile:
    try:
        scheme = urlparse(line).scheme.lower()
        if line.startswith("vmess://"):
            return _decode_vmess(line)
        if line.startswith("vless://"):
            return _decode_vless(line)
        if line.startswith("trojan://"):
            return _decode_trojan(line)
        if line.startswith("ss://"):
            return _decode_ss(line)
        if scheme in {"http", "https"}:
            return _decode_http_proxy(line)
        if scheme in {"socks", "socks5", "socks5h"}:
            return _decode_socks_proxy(line)
        raise ConfigError(f"unsupported uri format: {line[:24]}...")
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"invalid profile link: {line[:24]}...") from exc


def load_profiles(path: Path) -> list[Profile]:
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(
            "This file is not a text VPN config (UTF-8). Copy a supported link (vless/vmess/trojan/ss/http/socks) "
            "or a text .json/.conf file."
        ) from exc
    return load_profiles_from_text(content)


def load_profiles_from_text(content: str) -> list[Profile]:
    content = content.strip()
    if not content:
        raise ConfigError("empty config")

    if content.startswith("{"):
        data = json.loads(content)
        if "outbounds" in data:
            outbounds = [x for x in data["outbounds"] if x.get("type") != "direct"]
            profiles = []
            for i, outbound in enumerate(outbounds, start=1):
                name = outbound.get("tag") or outbound.get("server") or f"Profile {i}"
                profiles.append(Profile(name=name, outbound=outbound))
            if not profiles:
                raise ConfigError("no usable outbounds in json")
            return profiles

        if "server" in data and "type" in data:
            name = data.get("tag") or data.get("server") or "Profile 1"
            return [Profile(name=name, outbound=data)]

        raise ConfigError("json does not look like nekobox/sing-box config")

    profiles: list[Profile] = []
    last_error: ConfigError | None = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            profiles.append(parse_uri_line(line))
        except ConfigError as exc:
            last_error = exc

    if not profiles:
        if last_error is not None:
            raise last_error
        raise ConfigError("no links found")
    return profiles


def build_singbox_config(outbound: dict[str, Any], routing: RoutingOptions | None = None) -> dict[str, Any]:
    routing = routing or RoutingOptions()
    mode = routing.mode if routing.mode in {"all", "only_selected", "all_except_selected"} else "all"
    dns_mode = routing.dns_mode if routing.dns_mode in {"proxy", "direct", "custom"} else "proxy"
    custom_dns = routing.custom_dns.strip()
    domains = [x for x in routing.domains if x]
    rule_key = "domain_suffix" if routing.include_subdomains else "domain"
    # Rule order matters in sing-box: place sniff and domain routing before broad fallback rules.
    rules: list[dict[str, Any]] = [{"action": "sniff"}]
    dns_config: dict[str, Any] | None = None
    default_domain_resolver: str | None = None
    proxy_outbound = dict(outbound)
    raw_proxy_tag = str(proxy_outbound.get("tag") or "proxy").strip()
    proxy_tag = raw_proxy_tag if raw_proxy_tag and raw_proxy_tag not in {"direct", "block"} else "proxy"
    proxy_outbound["tag"] = proxy_tag
    outbounds: list[dict[str, Any]] = [
        proxy_outbound,
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    final_outbound = proxy_tag

    if dns_mode == "custom":
        if not custom_dns:
            raise ConfigError("custom dns is empty")
        parsed_custom = urlparse(custom_dns if "://" in custom_dns else f"udp://{custom_dns}")
        custom_type = (parsed_custom.scheme or "udp").lower()
        custom_server = parsed_custom.hostname
        custom_port = parsed_custom.port or 53
        if custom_type not in {"udp", "tcp"}:
            raise ConfigError("custom dns supports only udp/tcp")
        if not custom_server:
            raise ConfigError("custom dns address is invalid")
        dns_config = {
            "servers": [
                {
                    "tag": "custom-dns",
                    "type": custom_type,
                    "server": custom_server,
                    "server_port": custom_port,
                }
            ],
            "final": "custom-dns",
        }
        default_domain_resolver = "custom-dns"
        rules.append({"protocol": "dns", "action": "hijack-dns"})
    elif dns_mode == "proxy":
        # Force DNS via TCP through proxy so TCP-only profiles do not fail on UDP DNS.
        dns_config = {
            "servers": [
                {
                    "tag": "proxy-dns",
                    "type": "tcp",
                    "server": "1.1.1.1",
                    "server_port": 53,
                    "detour": proxy_tag,
                },
                {
                    "tag": "proxy-dns-fallback",
                    "type": "tcp",
                    "server": "8.8.8.8",
                    "server_port": 53,
                    "detour": proxy_tag,
                },
            ],
            "final": "proxy-dns",
        }
        default_domain_resolver = "proxy-dns"
        rules.append({"protocol": "dns", "action": "hijack-dns"})
    else:
        dns_config = {
            "servers": [
                {
                    "tag": "direct-dns",
                    "type": "udp",
                    "server": "1.1.1.1",
                    "server_port": 53,
                },
                {
                    "tag": "direct-dns-fallback",
                    "type": "udp",
                    "server": "8.8.8.8",
                    "server_port": 53,
                },
            ],
            "final": "direct-dns",
        }
        default_domain_resolver = "direct-dns"
        rules.append({"protocol": "dns", "action": "hijack-dns"})

    if mode == "only_selected":
        final_outbound = "direct"
        if domains:
            if _supports_udp(outbound):
                rules.append({rule_key: domains, "outbound": proxy_tag})
            else:
                # TCP-only proxies cannot carry UDP. Keep non-selected traffic direct and
                # explicitly reject selected-domain UDP to avoid ambiguous fallback behavior.
                rules.append({rule_key: domains, "network": ["udp"], "outbound": "block"})
                rules.append({rule_key: domains, "outbound": proxy_tag})
    elif mode == "all_except_selected":
        final_outbound = proxy_tag
        if domains:
            rules.append({rule_key: domains, "outbound": "direct"})

    if not _supports_udp(outbound) and mode in {"all", "all_except_selected"}:
        # Prevent endless UDP retry errors for TCP-only links (e.g. QUIC traffic).
        # This rule is intentionally placed after domain exceptions above.
        rules.append({"network": ["udp"], "outbound": "block"})

    config: dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "sb-tun",
                "mtu": 9000,
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
            }
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": rules,
            "final": final_outbound,
        },
        "outbounds": outbounds,
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": str(singbox_cache_path()),
            }
        },
    }
    if default_domain_resolver:
        config["route"]["default_domain_resolver"] = default_domain_resolver
    if dns_config is not None:
        config["dns"] = dns_config
    return config

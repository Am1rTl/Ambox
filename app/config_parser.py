import base64
import binascii
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

from app.app_paths import singbox_cache_path
from app.net_session import IFACE_NAME, ROUTE_TABLE, RULE_INDEX
from app.happ_links import HappLinkError, fetch_subscription, is_happ_link, unwrap_happ_link

RU_DOMAIN_SUFFIX = ".ru"


@dataclass
class Profile:
    name: str
    outbound: dict[str, Any]
    subscription_id: str | None = None
    # Full Xray config (outbounds + routing + balancers) for Happ-style subscriptions.
    xray: dict[str, Any] | None = None


@dataclass
class RoutingOptions:
    mode: str = "all"
    include_subdomains: bool = True
    ignore_ru_domains: bool = False
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


def normalize_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    """
    Fix fields written by older versions. In sing-box `network` restricts the outbound to one
    protocol, so the Xray stream network "tcp" stored there silently disabled UDP (and with it
    DNS-over-proxy, QUIC and voice calls); trojan has no `packet_encoding` and refuses to start.
    """
    out = dict(outbound)
    out_type = str(out.get("type", "")).lower()
    if out_type in {"vless", "vmess", "trojan"}:
        if str(out.get("network", "")).lower() == "tcp":
            out.pop("network")
        if out_type == "trojan":
            out.pop("packet_encoding", None)
        if out_type == "vless" and str(out.get("flow", "")).startswith("xtls-rprx-vision"):
            out["flow"] = "xtls-rprx-vision"
    return out


def _supports_udp(outbound: dict[str, Any]) -> bool:
    out_type = str(outbound.get("type", "")).lower()
    if out_type == "http":
        return False
    return str(outbound.get("network", "")).lower() != "tcp"


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
        "packet_encoding": "xudp",
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
        "packet_encoding": query.get("packetEncoding", ["xudp"])[0],
    }
    flow = query.get("flow", [""])[0]
    if flow:
        outbound["flow"] = "xtls-rprx-vision" if flow.startswith("xtls-rprx-vision") else flow

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


def _decode_hysteria2(uri: str) -> Profile:
    parsed = urlparse(uri)
    password = parsed.username or parsed.password or ""
    server = parsed.hostname
    if not server:
        raise ConfigError("hysteria2: missing server")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ConfigError("hysteria2: invalid port") from exc

    query = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else f"hy2-{server}"
    sni = query.get("sni", [server])[0]
    insecure = query.get("insecure", ["0"])[0] in {"1", "true"}

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
        },
    }
    if insecure:
        outbound["tls"]["insecure"] = True

    obfs_type = query.get("obfs", [""])[0]
    obfs_password = query.get("obfs-password", [""])[0]
    if obfs_type and obfs_password:
        outbound["obfs"] = {"type": obfs_type, "password": obfs_password}

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
        if line.startswith("hysteria2://") or line.startswith("hy2://"):
            return _decode_hysteria2(line)
        if line.startswith("ss://"):
            return _decode_ss(line)
        if scheme == "happ":
            try:
                target = unwrap_happ_link(line)
            except HappLinkError as exc:
                raise ConfigError(str(exc)) from exc
            target_scheme = urlparse(target).scheme.lower()
            if target_scheme in {"http", "https"}:
                raise ConfigError("Happ link points to a subscription URL; import it as a subscription")
            return parse_uri_line(target)
        if scheme in {"http", "https"}:
            from app.subscriptions import is_likely_subscription_url

            if is_likely_subscription_url(line):
                raise ConfigError("HTTP(S) link points to a subscription URL; import it as a subscription")
            return _decode_http_proxy(line)
        if scheme in {"socks", "socks5", "socks5h"}:
            return _decode_socks_proxy(line)
        raise ConfigError(f"unsupported uri format: {line[:24]}...")
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"invalid profile link: {line[:24]}...") from exc


def xray_to_singbox_outbound(ob: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(ob, dict):
        return None
    proto = str(ob.get("protocol") or ob.get("type") or "").lower()
    if proto in {"freedom", "blackhole", "direct", "block", ""}:
        return None

    settings = ob.get("settings") or {}
    stream = ob.get("streamSettings") or {}

    outbound: dict[str, Any] = {"tag": ob.get("tag") or "proxy"}
    server = ""
    port = 443

    if proto in {"vless", "vmess"}:
        vnext = settings.get("vnext") or []
        if not vnext or not isinstance(vnext, list) or not isinstance(vnext[0], dict):
            if "server" in ob and "uuid" in ob:
                # Already in sing-box format
                outbound = dict(ob)
                outbound["type"] = proto
                return outbound
            return None
        target = vnext[0]
        server = target.get("address") or ""
        try:
            port = int(target.get("port") or 443)
        except (ValueError, TypeError):
            port = 443
        users = target.get("users") or []
        if not users or not isinstance(users[0], dict):
            return None
        user = users[0]
        outbound["type"] = proto
        outbound["server"] = server
        outbound["server_port"] = port
        outbound["uuid"] = user.get("id") or ""
        outbound["packet_encoding"] = "xudp"
        flow = str(user.get("flow") or "")
        if proto == "vless" and flow:
            outbound["flow"] = "xtls-rprx-vision" if flow.startswith("xtls-rprx-vision") else flow
        if proto == "vmess":
            outbound["security"] = user.get("security") or "auto"
            try:
                outbound["alter_id"] = int(user.get("alterId") or 0)
            except (ValueError, TypeError):
                outbound["alter_id"] = 0
    elif proto == "trojan":
        servers = settings.get("servers") or []
        if not servers or not isinstance(servers[0], dict):
            if "server" in ob and "password" in ob:
                outbound = dict(ob)
                outbound["type"] = "trojan"
                return normalize_outbound(outbound)
            return None
        target = servers[0]
        server = target.get("address") or ""
        try:
            port = int(target.get("port") or 443)
        except (ValueError, TypeError):
            port = 443
        outbound["type"] = "trojan"
        outbound["server"] = server
        outbound["server_port"] = port
        outbound["password"] = target.get("password") or ""
    elif proto == "shadowsocks":
        servers = settings.get("servers") or []
        if not servers or not isinstance(servers[0], dict):
            if "server" in ob and "method" in ob:
                outbound = dict(ob)
                outbound["type"] = "shadowsocks"
                return outbound
            return None
        target = servers[0]
        server = target.get("address") or ""
        try:
            port = int(target.get("port") or 443)
        except (ValueError, TypeError):
            port = 443
        outbound["type"] = "shadowsocks"
        outbound["server"] = server
        outbound["server_port"] = port
        outbound["method"] = target.get("method") or ""
        outbound["password"] = target.get("password") or ""
    elif "server" in ob and ("type" in ob or "protocol" in ob):
        outbound = dict(ob)
        outbound["type"] = ob.get("type") or ob.get("protocol")
        return outbound
    else:
        return None

    network = (stream.get("network") or "tcp").lower()
    if network == "h2":
        network = "http"
    if network not in {"tcp", "raw", "ws", "http", "httpupgrade", "grpc", "quic"}:
        # xhttp/splithttp/kcp have no sing-box equivalent; treating them as plain TCP never works.
        return None
    tcp_header = ((stream.get("tcpSettings") or stream.get("rawSettings") or {}).get("header") or {}).get("type")
    if network in {"tcp", "raw"} and tcp_header and tcp_header != "none":
        return None

    if network in {"ws", "http", "httpupgrade"}:
        ws_settings = stream.get(f"{network}Settings") or stream.get("wsSettings") or {}
        transport: dict[str, Any] = {"type": network}
        if ws_settings.get("path"):
            transport["path"] = ws_settings["path"]
        headers = dict(ws_settings.get("headers") or {})
        host = ws_settings.get("host")
        if isinstance(host, list):
            host = host[0] if host else ""
        if host:
            if network == "http":
                transport["host"] = [host]
            else:
                headers.setdefault("Host", host)
        if headers:
            transport["headers"] = headers
        outbound["transport"] = transport
    elif network == "quic":
        outbound["transport"] = {"type": "quic"}
    elif network == "grpc":
        grpc_settings = stream.get("grpcSettings") or {}
        transport = {"type": "grpc"}
        if grpc_settings.get("serviceName"):
            transport["service_name"] = grpc_settings["serviceName"]
        outbound["transport"] = transport

    security = (stream.get("security") or "").lower()
    if security in {"tls", "reality"}:
        sec_settings = stream.get(f"{security}Settings") or stream.get("tlsSettings") or {}
        server_name = sec_settings.get("serverName") or sec_settings.get("sni") or server
        tls: dict[str, Any] = {
            "enabled": True,
            "server_name": server_name,
        }
        if sec_settings.get("allowInsecure"):
            tls["insecure"] = True
        alpn = sec_settings.get("alpn")
        if isinstance(alpn, list) and alpn:
            tls["alpn"] = [str(x) for x in alpn]
        fp = sec_settings.get("fingerprint")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            pbk = sec_settings.get("publicKey") or sec_settings.get("pbk")
            if pbk:
                tls["reality"] = {"enabled": True, "public_key": pbk}
                sid = sec_settings.get("shortId") or sec_settings.get("sid")
                if sid:
                    tls["reality"]["short_id"] = sid
        outbound["tls"] = tls

    return outbound


def _profile_from_xray_config(item: dict[str, Any], name: str) -> Profile | None:
    from app.xray_bundle import extract_xray_bundle, is_xray_bundle

    for ob in item.get("outbounds") or []:
        parsed_ob = xray_to_singbox_outbound(ob)
        if parsed_ob:
            xray = extract_xray_bundle(item) if is_xray_bundle(item) else None
            return Profile(name=name or ob.get("tag") or parsed_ob.get("server"), outbound=parsed_ob, xray=xray)
    return None


def _load_profiles_from_text(content: str, allow_happ_links: bool) -> list[Profile]:
    content = content.strip()
    if not content:
        raise ConfigError("empty config")

    if content.startswith("{") or content.startswith("["):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ConfigError("invalid json config") from exc

        profiles: list[Profile] = []
        if isinstance(data, list):
            for i, item in enumerate(data, start=1):
                if not isinstance(item, dict):
                    continue
                remarks = item.get("remarks") or item.get("name") or ""
                raw_outbounds = item.get("outbounds")
                if isinstance(raw_outbounds, list):
                    profile = _profile_from_xray_config(item, remarks or f"Profile {i}")
                    if profile:
                        profiles.append(profile)
                else:
                    parsed_ob = xray_to_singbox_outbound(item)
                    if parsed_ob:
                        name = remarks or item.get("tag") or parsed_ob.get("server") or f"Profile {i}"
                        profiles.append(Profile(name=name, outbound=parsed_ob))
            if profiles:
                return profiles
            raise ConfigError("no usable outbounds in json list")

        if not isinstance(data, dict):
            raise ConfigError("json config must be an object or list")

        if "profiles" in data and isinstance(data["profiles"], list):
            for i, item in enumerate(data["profiles"], start=1):
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                ob = item.get("outbound")
                if isinstance(ob, dict):
                    parsed_ob = xray_to_singbox_outbound(ob) or ob
                    xray = item.get("xray")
                    profiles.append(
                        Profile(
                            name=name or f"Profile {i}",
                            outbound=parsed_ob,
                            subscription_id=item.get("subscription_id"),
                            xray=xray if isinstance(xray, dict) else None,
                        )
                    )
            if profiles:
                return profiles
            raise ConfigError("no usable profiles in json")

        if "outbounds" in data:
            raw_outbounds = data.get("outbounds")
            if not isinstance(raw_outbounds, list):
                raise ConfigError("json outbounds must be a list")
            from app.xray_bundle import is_xray_bundle

            if is_xray_bundle(data):
                profile = _profile_from_xray_config(data, str(data.get("remarks") or "Profile 1"))
                if profile is None:
                    raise ConfigError("no usable outbounds in json")
                return [profile]
            for i, outbound in enumerate(raw_outbounds, start=1):
                if not isinstance(outbound, dict):
                    continue
                parsed_ob = xray_to_singbox_outbound(outbound)
                if parsed_ob:
                    name = outbound.get("tag") or parsed_ob.get("server") or f"Profile {i}"
                    profiles.append(Profile(name=name, outbound=parsed_ob))
            if not profiles:
                raise ConfigError("no usable outbounds in json")
            return profiles

        if isinstance(data.get("outbound"), dict):
            outbound = data["outbound"]
            parsed_ob = xray_to_singbox_outbound(outbound) or outbound
            name = data.get("name") or parsed_ob.get("tag") or parsed_ob.get("server") or "Profile 1"
            return [Profile(name=name, outbound=parsed_ob)]

        if "server" in data and ("type" in data or "protocol" in data):
            parsed_ob = xray_to_singbox_outbound(data) or data
            name = data.get("tag") or parsed_ob.get("server") or "Profile 1"
            return [Profile(name=name, outbound=parsed_ob)]

        raise ConfigError("json does not look like nekobox/sing-box config")

    profiles: list[Profile] = []
    last_error: ConfigError | None = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if allow_happ_links and is_happ_link(line):
                profiles.extend(load_happ_link(line))
            elif allow_happ_links and (line.startswith("http://") or line.startswith("https://")):
                from app.subscriptions import fetch_subscription_profiles, is_likely_subscription_url

                if is_likely_subscription_url(line):
                    sub_profiles, _, _ = fetch_subscription_profiles(line)
                    profiles.extend(sub_profiles)
                else:
                    profiles.append(parse_uri_line(line))
            else:
                profiles.append(parse_uri_line(line))
        except ConfigError as exc:
            last_error = exc

    if not profiles:
        if last_error is not None:
            raise last_error
        raise ConfigError("no links found")
    return profiles


def _load_subscription_content(content: str) -> list[Profile]:
    try:
        return _load_profiles_from_text(content, allow_happ_links=False)
    except ConfigError as first_error:
        try:
            decoded = _decode_base64_text(content.strip(), "subscription")
        except ConfigError:
            raise first_error
        try:
            return _load_profiles_from_text(decoded, allow_happ_links=False)
        except ConfigError as exc:
            raise exc from first_error


def load_happ_link(link: str, fetcher: Callable[[str], str] | None = None) -> list[Profile]:
    try:
        target = unwrap_happ_link(link)
    except HappLinkError as exc:
        raise ConfigError(str(exc)) from exc

    target_scheme = urlparse(target).scheme.lower()
    if target_scheme not in {"http", "https"}:
        return _load_profiles_from_text(target, allow_happ_links=False)

    try:
        content = (fetcher or fetch_subscription)(target)
    except HappLinkError as exc:
        raise ConfigError(str(exc)) from exc
    return _load_subscription_content(content)


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
    return _load_profiles_from_text(content, allow_happ_links=True)


def _direct_dns_server() -> dict[str, Any]:
    return {
        "tag": "direct-dns",
        "type": "udp",
        "server": "1.1.1.1",
        "server_port": 53,
    }


def convert_bundle_outbound(ob: dict[str, Any]) -> dict[str, Any] | None:
    converted = xray_to_singbox_outbound(ob)
    return normalize_outbound(converted) if converted else None


def build_singbox_config(
    outbound: dict[str, Any],
    routing: RoutingOptions | None = None,
    xray: dict[str, Any] | None = None,
    rule_set_available: Callable[[str, str], bool] | None = None,
    unavailable: set[str] | None = None,
) -> dict[str, Any]:
    from app.xray_bundle import cached_rule_set_available, convert_xray_bundle, rule_set_path

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
    bundle = None
    if xray:
        try:
            bundle = convert_xray_bundle(
                xray,
                convert_bundle_outbound,
                rule_set_available or cached_rule_set_available,
                unavailable or frozenset(),
            )
        except ValueError:
            bundle = None
    if bundle is not None:
        proxy_outbounds = bundle.outbounds
        proxy_tag = bundle.main_tag
        bundle_final = bundle.final_tag
    else:
        proxy_outbound = normalize_outbound(outbound)
        raw_proxy_tag = str(proxy_outbound.get("tag") or "proxy").strip()
        proxy_tag = raw_proxy_tag if raw_proxy_tag and raw_proxy_tag not in {"direct", "block"} else "proxy"
        proxy_outbound["tag"] = proxy_tag
        proxy_outbounds = [proxy_outbound]
        bundle_final = proxy_tag
    outbounds: list[dict[str, Any]] = [
        *proxy_outbounds,
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    final_outbound = bundle_final

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
        dns_config = {
            "servers": [
                {
                    "tag": "proxy-dns",
                    "type": "udp",
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
                _direct_dns_server(),
            ],
            "final": "proxy-dns",
        }
        default_domain_resolver = "direct-dns"
        rules.append({"protocol": "dns", "action": "hijack-dns"})
    else:
        dns_config = {
            "servers": [
                _direct_dns_server(),
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

    # Never send loopback requests into the TUN/proxy, regardless of routing mode.
    rules.extend(
        [
            {"domain": ["localhost"], "outbound": "direct"},
            {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
        ]
    )

    if routing.ignore_ru_domains:
        rules.append({"domain_suffix": [RU_DOMAIN_SUFFIX], "outbound": "direct"})
        if dns_mode == "proxy" and dns_config is not None:
            dns_config["rules"] = [
                {"domain_suffix": [RU_DOMAIN_SUFFIX], "action": "route", "server": "direct-dns"}
            ]

    udp_ok = bundle is not None or _supports_udp(proxy_outbounds[0])
    if mode == "only_selected":
        final_outbound = "direct"
        if domains:
            if udp_ok:
                rules.append({rule_key: domains, "outbound": proxy_tag})
            else:
                # TCP-only proxies cannot carry UDP. Keep non-selected traffic direct and
                # explicitly reject selected-domain UDP to avoid ambiguous fallback behavior.
                rules.append({rule_key: domains, "network": ["udp"], "outbound": "block"})
                rules.append({rule_key: domains, "outbound": proxy_tag})
    elif mode == "all_except_selected":
        if domains:
            rules.append({rule_key: domains, "outbound": "direct"})

    if bundle is not None and mode != "only_selected":
        # The provider's own routing (per-service nodes, balancers, direct lists) comes after the
        # user's exceptions above.
        rules.extend(bundle.rules)

    if not udp_ok and mode in {"all", "all_except_selected"}:
        # Prevent endless UDP retry errors for TCP-only links (e.g. QUIC traffic).
        # This rule is intentionally placed after domain exceptions above.
        rules.append({"network": ["udp"], "outbound": "block"})

    config: dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": IFACE_NAME,
                "mtu": 9000,
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                # Own table / rule priorities: never collide with other TUN clients (e.g. Happ 2022 / 9000).
                "iproute2_table_index": ROUTE_TABLE,
                "iproute2_rule_index": RULE_INDEX,
            }
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": rules,
            "final": final_outbound,
        },
        "outbounds": outbounds,
    }
    if bundle is not None and mode != "only_selected" and bundle.rule_sets:
        config["route"]["rule_set"] = [
            {"type": "local", "tag": tag, "format": "binary", "path": str(rule_set_path(kind, name))}
            for tag, (kind, name) in sorted(bundle.rule_sets.items())
        ]
    if default_domain_resolver:
        config["route"]["default_domain_resolver"] = default_domain_resolver
    if dns_config is not None:
        config["dns"] = dns_config
    return config

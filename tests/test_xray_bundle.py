import json

from app.config_parser import RoutingOptions, build_singbox_config, load_profiles_from_text, normalize_outbound
from app.xray_bundle import required_rule_sets


def _vless(tag: str, address: str, network: str = "tcp") -> dict:
    stream = {
        "network": network,
        "security": "reality",
        "realitySettings": {"serverName": "sni.example.com", "publicKey": "pbk", "fingerprint": "firefox"},
    }
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": address, "port": 443, "users": [{"id": "uuid", "flow": "xtls-rprx-vision"}]}]
        },
        "streamSettings": stream,
    }


def _happ_config() -> dict:
    return {
        "remarks": "🇫🇷 France",
        "outbounds": [
            _vless("proxy-vless-reality-1", "10.0.0.1"),
            _vless("proxy-youtube-1", "10.0.0.2"),
            _vless("proxy-youtube-2", "10.0.0.3"),
            _vless("proxy-abuse-1", "10.0.0.4"),
            _vless("proxy-abuse-2", "10.0.0.5"),
            _vless("proxy-xhttp", "10.0.0.6", network="xhttp"),
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "observatory": {"probeURL": "https://cloudflare.com/cdn-cgi/trace"},
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {"tag": "balancer", "selector": ["proxy-vless-reality-"], "fallbackTag": "proxy-vless-reality-1"},
                {"tag": "balancer-youtube", "selector": ["proxy-youtube-1", "proxy-youtube-2"]},
                {"tag": "balancer-abuse", "selector": ["proxy-abuse-"]},
            ],
            "rules": [
                {"domain": ["geosite:youtube"], "network": "udp", "port": "443", "outboundTag": "block"},
                {"domain": ["geosite:youtube"], "balancerTag": "balancer-youtube"},
                {"domain": ["geosite:missing"], "outboundTag": "proxy-abuse-1"},
                {"domain": ["domain:example.org", "full:exact.example.org"], "outboundTag": "direct"},
                {"inboundTag": ["api"], "outboundTag": "direct"},
                {"ip": ["geoip:private", "1.2.3.4"], "outboundTag": "direct"},
                {"network": "udp", "port": "3478-3497,4244", "balancerTag": "balancer"},
                {"type": "field", "port": "22,443", "balancerTag": "balancer"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "balancer-abuse"},
            ],
        },
    }


def _build(profile, **kwargs):
    available = lambda kind, name: (kind, name) == ("geosite", "youtube")  # noqa: E731
    return build_singbox_config(profile.outbound, RoutingOptions(), xray=profile.xray, rule_set_available=available, **kwargs)


def test_happ_config_keeps_full_xray_bundle() -> None:
    profiles = load_profiles_from_text(json.dumps([_happ_config()]))
    assert len(profiles) == 1
    assert profiles[0].name == "🇫🇷 France"
    assert profiles[0].outbound["server"] == "10.0.0.1"
    assert profiles[0].xray is not None
    assert required_rule_sets(profiles[0].xray) == {("geosite", "youtube"), ("geosite", "missing")}


def test_happ_config_converts_balancers_and_rules() -> None:
    profile = load_profiles_from_text(json.dumps([_happ_config()]))[0]
    config = _build(profile)
    outbounds = {ob["tag"]: ob for ob in config["outbounds"]}

    # xhttp has no sing-box transport and must not be turned into plain TCP.
    assert "proxy-xhttp" not in outbounds
    assert outbounds["balancer-youtube"]["type"] == "urltest"
    assert outbounds["balancer-youtube"]["outbounds"] == ["proxy-youtube-1", "proxy-youtube-2"]
    assert outbounds["balancer-youtube"]["url"] == "https://cloudflare.com/cdn-cgi/trace"
    assert outbounds["balancer-abuse"]["outbounds"] == ["proxy-abuse-1", "proxy-abuse-2"]
    # Single-member balancer is an alias of its node; the Xray catch-all rule becomes route.final.
    assert "balancer" not in outbounds
    assert config["route"]["final"] == "balancer-abuse"
    assert all("network" not in ob for ob in config["outbounds"] if ob["type"] == "vless")

    rules = config["route"]["rules"]
    assert {"network": ["udp"], "port": [443], "rule_set": ["geosite-youtube"], "action": "reject"} in rules
    assert {"rule_set": ["geosite-youtube"], "outbound": "balancer-youtube"} in rules
    assert {"domain_suffix": ["example.org"], "domain": ["exact.example.org"], "outbound": "direct"} in rules
    assert {"ip_is_private": True, "ip_cidr": ["1.2.3.4/32"], "outbound": "direct"} in rules
    assert {
        "network": ["udp"],
        "port": [4244],
        "port_range": ["3478:3497"],
        "outbound": "proxy-vless-reality-1",
    } in rules
    # Rules with unavailable rule-sets or Xray inbounds are dropped instead of matching everything.
    assert not any(r.get("outbound") == "proxy-abuse-1" for r in rules)
    assert {"action": "resolve", "strategy": "prefer_ipv4"} in rules
    assert rules.index({"action": "resolve", "strategy": "prefer_ipv4"}) < rules.index(
        {"ip_is_private": True, "ip_cidr": ["1.2.3.4/32"], "outbound": "direct"}
    )
    assert [rs["tag"] for rs in config["route"]["rule_set"]] == ["geosite-youtube"]
    assert config["dns"]["servers"][0]["detour"] == "proxy-vless-reality-1"


def test_happ_config_falls_back_when_main_node_is_unreachable() -> None:
    profile = load_profiles_from_text(json.dumps([_happ_config()]))[0]
    config = _build(profile, unavailable={"proxy-vless-reality-1", "proxy-youtube-2"})
    outbounds = {ob["tag"]: ob for ob in config["outbounds"]}

    assert "proxy-vless-reality-1" not in outbounds
    assert outbounds["auto"]["type"] == "urltest"
    assert outbounds["auto"]["outbounds"] == ["proxy-youtube-1", "proxy-abuse-1", "proxy-abuse-2"]
    assert "balancer-youtube" not in outbounds
    assert config["dns"]["servers"][0]["detour"] == "auto"
    rules = config["route"]["rules"]
    assert {"rule_set": ["geosite-youtube"], "outbound": "proxy-youtube-1"} in rules
    assert {"port": [22, 443], "outbound": "auto"} in rules


def test_only_selected_mode_ignores_provider_rules() -> None:
    profile = load_profiles_from_text(json.dumps([_happ_config()]))[0]
    config = build_singbox_config(
        profile.outbound,
        RoutingOptions(mode="only_selected", domains=["example.com"]),
        xray=profile.xray,
        rule_set_available=lambda kind, name: True,
    )
    assert config["route"]["final"] == "direct"
    assert {"domain_suffix": ["example.com"], "outbound": "proxy-vless-reality-1"} in config["route"]["rules"]
    assert "rule_set" not in config["route"]


def test_normalize_outbound_restores_udp_and_fixes_trojan() -> None:
    vless = normalize_outbound({"type": "vless", "network": "tcp", "flow": "xtls-rprx-vision-udp443"})
    assert "network" not in vless
    assert vless["flow"] == "xtls-rprx-vision"
    trojan = normalize_outbound({"type": "trojan", "network": "tcp", "packet_encoding": "xudp"})
    assert "network" not in trojan and "packet_encoding" not in trojan

    config = build_singbox_config({"type": "vless", "tag": "proxy", "network": "tcp", "packet_encoding": "xudp"})
    assert "network" not in config["outbounds"][0]
    assert {"network": ["udp"], "outbound": "block"} not in config["route"]["rules"]


def test_ignore_ru_with_proxy_dns_has_unique_dns_tags() -> None:
    config = build_singbox_config(
        {"type": "vless", "tag": "proxy", "server": "1.2.3.4", "server_port": 443, "uuid": "u"},
        RoutingOptions(dns_mode="proxy", ignore_ru_domains=True),
    )
    tags = [server["tag"] for server in config["dns"]["servers"]]
    assert len(tags) == len(set(tags))

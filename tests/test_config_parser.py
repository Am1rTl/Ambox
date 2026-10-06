import base64
import json
from urllib.parse import quote

import pytest

from app.config_parser import (
    ConfigError,
    RoutingOptions,
    build_singbox_config,
    load_happ_link,
    load_profiles_from_text,
    parse_domains_text,
)


def test_load_vmess_profile() -> None:
    payload = {
        "v": "2",
        "ps": "vmess-test",
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "aid": "0",
        "net": "ws",
        "path": "/ws",
        "host": "cdn.example.com",
        "tls": "tls",
        "sni": "example.com",
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    profiles = load_profiles_from_text(f"vmess://{encoded}")
    assert len(profiles) == 1
    assert profiles[0].name == "vmess-test"
    assert profiles[0].outbound["type"] == "vmess"
    assert profiles[0].outbound["transport"]["type"] == "ws"


def test_load_vless_profile() -> None:
    text = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?security=tls&type=ws&host=cdn.example.com&path=%2Fws#MyVless"
    )
    profiles = load_profiles_from_text(text)
    assert len(profiles) == 1
    assert profiles[0].name == "MyVless"
    assert profiles[0].outbound["type"] == "vless"


def test_load_trojan_profile() -> None:
    profiles = load_profiles_from_text("trojan://secret@example.com:443?security=tls#TrojanNode")
    assert len(profiles) == 1
    assert profiles[0].name == "TrojanNode"
    assert profiles[0].outbound["type"] == "trojan"


def test_load_ss_profile() -> None:
    payload = base64.urlsafe_b64encode(b"aes-256-gcm:pass123@example.com:8388").decode("ascii")
    profiles = load_profiles_from_text(f"ss://{payload}#SSNode")
    assert len(profiles) == 1
    assert profiles[0].name == "SSNode"
    assert profiles[0].outbound["type"] == "shadowsocks"


def test_load_happ_add_link() -> None:
    profile_link = "vless://11111111-1111-1111-1111-111111111111@example.com:443#HappNode"
    profiles = load_happ_link(f"happ://add/{quote(profile_link, safe='')}")
    assert len(profiles) == 1
    assert profiles[0].name == "HappNode"
    assert profiles[0].outbound["type"] == "vless"


def test_load_happ_add_subscription() -> None:
    profile_link = "trojan://secret@example.com:443#SubscriptionNode"
    requested_urls: list[str] = []

    def fetch(url: str) -> str:
        requested_urls.append(url)
        return profile_link

    profiles = load_happ_link("happ://add/https://example.com/sub?token=secret", fetch)
    assert requested_urls == ["https://example.com/sub?token=secret"]
    assert profiles[0].name == "SubscriptionNode"


def test_load_happ_base64_subscription() -> None:
    profile_link = "socks://user:pass@example.com:1080#Base64Node"
    encoded = base64.urlsafe_b64encode(profile_link.encode()).decode().rstrip("=")
    profiles = load_happ_link("happ://add/https://example.com/sub", lambda _url: encoded)
    assert profiles[0].name == "Base64Node"


def test_load_hysteria2_profile() -> None:
    profiles = load_profiles_from_text("hysteria2://secret@example.com:443?sni=sni.example.com&insecure=1#MyHy2")
    assert len(profiles) == 1
    assert profiles[0].name == "MyHy2"
    assert profiles[0].outbound["type"] == "hysteria2"
    assert profiles[0].outbound["server"] == "example.com"
    assert profiles[0].outbound["server_port"] == 443
    assert profiles[0].outbound["password"] == "secret"
    assert profiles[0].outbound["tls"]["insecure"] is True


def test_load_happ_crypt5_subscription() -> None:
    payload = "fzvdO4bMOfTWNaB3taWRhRaF64soexaE9dm3ZlLK0Rke9Rz3BG1f9gmj4tSDpjRSWWdX5G6oaaQK9Gs+fdJPWNXIF08BsaeifWtfTlCvC/nSWDv0ZrofgJXkQ8MlUk63CoJkt7RvXAfablYXb/cYWEZJQkDMyMaE5/1KegAbWVWVI60MPqDylUyYoLtOeOOX9amvELecOZ4kKz1QVqgE9uCBz3py+3Ghr1iVGKOhFwb98OFP+j0tGvDo/3d609DVq3RwBGXu1ogZ7PTc3/A5IlaA3Hff5IlVujozQ3ywmQBsTGd+l3AHJAX1oDbPkRSSwg7Y7hl3AKXKpZsEhMzPbJY8UxZ7GmVsxeROLopVx85ACqakzg+ZZwdZslfKgdRzUmL9Mv895HDOHE3tbh6qnDhE9Ew/Epx1iBCb2HjorOLDBluH8ztdL9mdUX+turjC4GLN0YR55P3H23A0W5zl0di5YfrI2nUBKxh30lUVG9NbqYKlwxgmhxAUZrQ6cnFGF2VuZ9VJLQ3sQ8rqXTtfau8ySbu770Hd6vVEun8aSJm4W4M0DagKbORL4A4M6Cuf1v/jj7EWhA9yhhcSuxkc6WUWMGYRraWBM9vSrSbjeT1U69a3n9T56M/TOJWf4z8fXrHRnCR1tfzwrjHiOJfZGiKvbAd4k6f+VADYpLdCq+ornEElv7V0sByfwPTgep+Q33Qkl67ArHpmbZDcCyWkGz0BoUzGJFe58YiS/oNFVdufbuDnFd1ArAVMztJJJbxlo4Is48+Iof=ff"
    requested_urls: list[str] = []

    def fetch(url: str) -> str:
        requested_urls.append(url)
        return "vless://11111111-1111-1111-1111-111111111111@example.com:443#Crypt5Node"

    profiles = load_happ_link(f"happ://crypt5/{payload}", fetch)
    assert requested_urls == ["https://example.com/sub"]
    assert len(profiles) == 1
    assert profiles[0].name == "Crypt5Node"


def test_happ_crypt_link_invalid_is_rejected() -> None:
    with pytest.raises(ConfigError, match="failed to decrypt"):
        load_happ_link("happ://crypt5/encrypted-payload")


def test_happ_unknown_action_is_rejected() -> None:
    with pytest.raises(ConfigError, match="unsupported Happ action"):
        load_happ_link("happ://connect")


def test_load_singbox_json_outbounds() -> None:
    data = {
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "socks", "tag": "proxy-a", "server": "one.example", "server_port": 1080},
            {"type": "http", "tag": "proxy-b", "server": "two.example", "server_port": 8080},
        ]
    }
    profiles = load_profiles_from_text(json.dumps(data))
    assert [profile.name for profile in profiles] == ["proxy-a", "proxy-b"]


def test_load_xray_json_array() -> None:
    data = [
        {
            "remarks": "🇫🇮 Finland Node",
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "proxy-1",
                    "settings": {
                        "vnext": [
                            {
                                "address": "1.2.3.4",
                                "port": 443,
                                "users": [{"id": "uuid-1234", "flow": "xtls-rprx-vision"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "sni.example.com",
                            "publicKey": "test-pbk",
                            "fingerprint": "chrome",
                        },
                    },
                },
                {"protocol": "freedom", "tag": "direct"},
            ],
        }
    ]
    profiles = load_profiles_from_text(json.dumps(data))
    assert len(profiles) == 1
    assert profiles[0].name == "🇫🇮 Finland Node"
    assert profiles[0].outbound["type"] == "vless"
    assert profiles[0].outbound["server"] == "1.2.3.4"
    assert profiles[0].outbound["server_port"] == 443
    assert profiles[0].outbound["uuid"] == "uuid-1234"
    assert profiles[0].outbound["flow"] == "xtls-rprx-vision"
    assert profiles[0].outbound["tls"]["reality"]["public_key"] == "test-pbk"
    assert profiles[0].outbound["tls"]["utls"]["fingerprint"] == "chrome"


def test_invalid_input_raises_last_error() -> None:
    try:
        load_profiles_from_text("not-a-valid-config")
    except ConfigError as exc:
        assert "unsupported uri format" in str(exc)
    else:
        raise AssertionError("ConfigError was not raised")


def test_parse_domains_text_deduplicates_and_normalizes() -> None:
    domains = parse_domains_text("*.Example.com\nhttps://sub.example.com/path\nexample.com\n")
    assert domains == ["example.com", "sub.example.com"]


def test_build_singbox_config_custom_dns() -> None:
    profiles = load_profiles_from_text("socks://user:pass@example.com:1080#SocksNode")
    config = build_singbox_config(
        profiles[0].outbound,
        routing=None,
    )
    assert config["route"]["final"] == "proxy"
    assert config["dns"]["final"] == "proxy-dns"


def test_build_singbox_config_can_ignore_ru_domains() -> None:
    profiles = load_profiles_from_text("socks://user:pass@example.com:1080#SocksNode")
    config = build_singbox_config(
        profiles[0].outbound,
        routing=RoutingOptions(mode="only_selected", domains=["example.ru"], ignore_ru_domains=True),
    )

    rules = config["route"]["rules"]
    direct_rule = {"domain_suffix": [".ru"], "outbound": "direct"}
    proxy_rule = {"domain_suffix": ["example.ru"], "outbound": "proxy"}
    assert direct_rule in rules
    assert proxy_rule in rules
    assert rules.index(direct_rule) < rules.index(proxy_rule)
    assert {"domain_suffix": [".ru"], "action": "route", "server": "direct-dns"} in config["dns"]["rules"]


def test_build_singbox_config_keeps_localhost_direct() -> None:
    profiles = load_profiles_from_text("socks://user:pass@example.com:1080#SocksNode")

    for mode in ("all", "only_selected", "all_except_selected"):
        config = build_singbox_config(
            profiles[0].outbound,
            routing=RoutingOptions(mode=mode, domains=["example.com"]),
        )

        rules = config["route"]["rules"]
        localhost_rule = {"domain": ["localhost"], "outbound": "direct"}
        loopback_rule = {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"}
        assert localhost_rule in rules
        assert loopback_rule in rules
        assert rules.index(localhost_rule) < rules.index(loopback_rule)

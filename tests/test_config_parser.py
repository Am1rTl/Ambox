import base64
import json

from app.config_parser import ConfigError, build_singbox_config, load_profiles_from_text, parse_domains_text


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

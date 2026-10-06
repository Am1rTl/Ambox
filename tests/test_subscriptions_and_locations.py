import base64
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key

from app.happ_crypto_keys import PKCS1_KEYS
from app.happ_links import parse_subscription_userinfo, unwrap_happ_link
from app.locations import detect_location, iso_to_flag
from app.subscriptions import (
    Subscription,
    SubscriptionStore,
    derive_subscription_name,
    fetch_subscription_profiles,
    format_bytes,
    generate_subscription_id,
    is_likely_subscription_url,
)
from app.config_parser import Profile


def test_locations_detection_flag_emoji() -> None:
    loc = detect_location("🇩🇪 Germany Fast Node", "example.com")
    assert loc.code == "DE"
    assert loc.flag == "🇩🇪"
    assert loc.name == "Germany"

    loc_nl = detect_location("Amsterdam 🇳🇱 #1", "example.com")
    assert loc_nl.code == "NL"
    assert loc_nl.flag == "🇳🇱"


def test_locations_detection_keywords_and_iso() -> None:
    assert detect_location("[US] New York 01").code == "US"
    assert detect_location("(FI) Helsinki").code == "FI"
    assert detect_location("Нидерланды Amsterdam").code == "NL"
    assert detect_location("Германия Франкфурт").code == "DE"
    assert detect_location("Россия Москва").code == "RU"
    assert detect_location("Japan Tokyo Premium").code == "JP"
    assert detect_location("Turkey Istanbul Fast").code == "TR"
    assert detect_location("Kazakhstan Almaty").code == "KZ"
    assert detect_location("Singapore Cloud").code == "SG"
    assert detect_location("United Kingdom London").code == "GB"


def test_locations_detection_domain_heuristics() -> None:
    loc_de = detect_location("Node-1", "fra.server.de")
    assert loc_de.code == "DE"

    loc_nl = detect_location("Node-2", "ams-node.myvpn.net")
    assert loc_nl.code == "NL"

    loc_unknown = detect_location("Random Name", "unknown-domain.io")
    assert loc_unknown.code == "XX"
    assert loc_unknown.flag == "🌐"


def test_iso_to_flag() -> None:
    assert iso_to_flag("DE") == "🇩🇪"
    assert iso_to_flag("US") == "🇺🇸"
    assert iso_to_flag("NL") == "🇳🇱"
    assert iso_to_flag("XX") == "🌐"


def test_subscription_userinfo_summary() -> None:
    sub = Subscription(
        id="sub1",
        name="Test Sub",
        url="https://example.com/sub",
        user_info={
            "upload": 1024 * 1024 * 1024,
            "download": 4 * 1024 * 1024 * 1024,
            "total": 50 * 1024 * 1024 * 1024,
            "expire": 1800000000,
        },
    )
    summary = sub.userinfo_summary()
    assert "Traffic: 5.0 GB / 50.0 GB" in summary
    assert "Expires:" in summary


def test_subscription_store(tmp_path: Path) -> None:
    store_file = tmp_path / "subscriptions.json"
    store = SubscriptionStore(store_file)
    assert len(store.all()) == 0

    sub = Subscription(
        id="s1",
        name="My VPN",
        url="https://vpn.example/sub",
        profile_count=5,
    )
    store.put(sub)
    assert len(store.all()) == 1
    assert store.get("s1") is not None
    assert store.get("s1").name == "My VPN"

    # Reload from file
    store2 = SubscriptionStore(store_file)
    assert len(store2.all()) == 1
    assert store2.get("s1").profile_count == 5

    store2.remove("s1")
    assert len(store2.all()) == 0


def test_is_likely_subscription_url() -> None:
    assert is_likely_subscription_url("happ://add/https://example.com/sub") is True
    assert is_likely_subscription_url("https://example.com/sub/token123") is True
    assert is_likely_subscription_url("https://provider.org/api/v1/client/subscribe?token=secret") is True
    assert is_likely_subscription_url("https://normal-website.com") is False


def test_happ_extended_schemes() -> None:
    assert unwrap_happ_link("happ://subscribe/https://sub.example/vpn") == "https://sub.example/vpn"
    assert unwrap_happ_link("happ://sub/https://sub.example/vpn") == "https://sub.example/vpn"
    assert unwrap_happ_link("happ://https://sub.example/vpn") == "https://sub.example/vpn"


def test_happ_crypt_rsa_link() -> None:
    # Encrypt a target URL using crypt1 RSA key
    key_der = base64.b64decode(PKCS1_KEYS["crypt"])
    key = load_der_private_key(key_der, password=None)
    pub = key.public_key()
    target_url = b"https://secret.subscription.net/sub"
    enc = pub.encrypt(target_url, padding.PKCS1v15())
    enc_b64 = base64.urlsafe_b64encode(enc).decode().rstrip("=")

    link = f"happ://crypt/{enc_b64}"
    unwrapped = unwrap_happ_link(link)
    assert unwrapped == "https://secret.subscription.net/sub"


def test_fetch_subscription_profiles() -> None:
    sub_content = "vless://11111111-1111-1111-1111-111111111111@de.example.com:443#DE-Node\ntrojan://secret@nl.example.com:443#NL-Node"

    def mock_fetcher(url: str):
        return sub_content, {
            "profile_title": "CustomTitle",
            "user_info": {"upload": 100, "download": 200, "total": 1000},
        }

    profiles, target, headers = fetch_subscription_profiles("happ://add/https://example.com/sub", mock_fetcher)
    assert len(profiles) == 2
    assert profiles[0].name == "DE-Node"
    assert profiles[1].name == "NL-Node"
    assert headers["profile_title"] == "CustomTitle"
    assert headers["user_info"]["total"] == 1000


def test_derive_subscription_name_base64() -> None:
    headers = {"profile_title": "base64:SGlyb1ZQTg=="}
    name = derive_subscription_name("https://example.com/sub", headers)
    assert name == "HiroVPN"

    headers_plain = {"profile_title": "MyPlainVPN"}
    name_plain = derive_subscription_name("https://example.com/sub", headers_plain)
    assert name_plain == "MyPlainVPN"


def test_xray_outbound_vmess_and_trojan_conversion() -> None:
    from app.config_parser import xray_to_singbox_outbound

    # VMess Xray outbound
    vmess_xray = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": "vmess.example.com",
                    "port": 8443,
                    "users": [{"id": "uuid-vmess-1", "alterId": 16, "security": "aes-128-gcm"}],
                }
            ]
        },
        "streamSettings": {
            "network": "ws",
            "wsSettings": {"path": "/vpath", "headers": {"Host": "vhost.com"}},
            "security": "tls",
            "tlsSettings": {"serverName": "sni.vmess.com"},
        },
    }
    converted_vmess = xray_to_singbox_outbound(vmess_xray)
    assert converted_vmess is not None
    assert converted_vmess["type"] == "vmess"
    assert converted_vmess["server"] == "vmess.example.com"
    assert converted_vmess["server_port"] == 8443
    assert converted_vmess["uuid"] == "uuid-vmess-1"
    assert converted_vmess["alter_id"] == 16
    assert converted_vmess["transport"]["type"] == "ws"
    assert converted_vmess["transport"]["path"] == "/vpath"
    assert converted_vmess["tls"]["server_name"] == "sni.vmess.com"

    # Trojan Xray outbound
    trojan_xray = {
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": "trojan.example.com", "port": 443, "password": "mypassword"}]
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {"serviceName": "trojan-grpc"},
            "security": "tls",
        },
    }
    converted_trojan = xray_to_singbox_outbound(trojan_xray)
    assert converted_trojan is not None
    assert converted_trojan["type"] == "trojan"
    assert converted_trojan["server"] == "trojan.example.com"
    assert converted_trojan["password"] == "mypassword"
    assert converted_trojan["transport"]["type"] == "grpc"
    assert converted_trojan["transport"]["service_name"] == "trojan-grpc"

from unittest.mock import patch

from app import happ_links
from app.happ_links import HAPP_HWID, fetch_subscription_with_info


class _FakeHeaders:
    def __init__(self, values=None):
        self._values = values or {}

    def get(self, name, default=None):
        for key, value in self._values.items():
            if key.lower() == name.lower():
                return value
        return default


class _FakeResponse:
    def __init__(self, body=b"vless://x", headers=None):
        self._body = body
        self.headers = _FakeHeaders(headers)

    def read(self, _size=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _header_dict(request) -> dict[str, str]:
    result: dict[str, str] = {}
    if hasattr(request, "header_items"):
        for key, value in request.header_items():
            result[key.lower()] = value
    result.update({k.lower(): v for k, v in request.unredirected_hdrs.items()})
    return result


def test_fetch_sends_patched_hwid_by_default() -> None:
    assert HAPP_HWID == "cafebabecafebabe"
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["request"] = request
        return _FakeResponse()

    with patch.object(happ_links, "urlopen", fake_urlopen):
        text, _info = fetch_subscription_with_info("https://example.com/sub")

    assert text == "vless://x"
    headers = _header_dict(captured["request"])
    assert headers["x-hwid"] == "cafebabecafebabe"
    assert headers["x-device-os"] == "Android"
    assert headers["x-ver-os"]
    assert headers["x-device-model"]
    assert headers["x-device-locale"]


def test_fetch_allows_hwid_override() -> None:
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["request"] = request
        return _FakeResponse()

    with patch.object(happ_links, "urlopen", fake_urlopen):
        fetch_subscription_with_info("https://example.com/sub", hwid="custom-hwid")

    headers = _header_dict(captured["request"])
    assert headers["x-hwid"] == "custom-hwid"

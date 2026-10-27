import time

import pytest

from app import latency


@pytest.fixture(autouse=True)
def _clean_cache():
    latency.clear_latency_cache()
    yield
    latency.clear_latency_cache()


def _dummy_outbound():
    return {
        "type": "socks",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": 1,
        "version": "5",
    }


class _DummySock:
    def close(self):
        pass


def test_cache_hit_avoids_second_probe(monkeypatch):
    monkeypatch.setattr(latency, "_find_singbox", lambda: None)
    calls = []

    def fake_create_connection(endpoint, timeout=None):
        calls.append(endpoint)
        return _DummySock()

    monkeypatch.setattr(latency.socket, "create_connection", fake_create_connection)
    first = latency.outbound_latency_ms(_dummy_outbound(), timeout_sec=1)
    second = latency.outbound_latency_ms(_dummy_outbound(), timeout_sec=1)
    assert first is not None
    assert first == second
    assert len(calls) == 1


def test_failures_are_cached_too(monkeypatch):
    monkeypatch.setattr(latency, "_find_singbox", lambda: None)
    calls = []

    def fake_create_connection(endpoint, timeout=None):
        calls.append(endpoint)
        raise OSError("unreachable")

    monkeypatch.setattr(latency.socket, "create_connection", fake_create_connection)
    assert latency.outbound_latency_ms(_dummy_outbound(), timeout_sec=1) is None
    assert latency.outbound_latency_ms(_dummy_outbound(), timeout_sec=1) is None
    assert len(calls) == 1


def test_use_cache_false_bypasses_cache(monkeypatch):
    monkeypatch.setattr(latency, "_find_singbox", lambda: None)
    calls = []

    def fake_create_connection(endpoint, timeout=None):
        calls.append(endpoint)
        return _DummySock()

    monkeypatch.setattr(latency.socket, "create_connection", fake_create_connection)
    latency.outbound_latency_ms(_dummy_outbound(), timeout_sec=1, use_cache=False)
    latency.outbound_latency_ms(_dummy_outbound(), timeout_sec=1, use_cache=False)
    assert len(calls) == 2


def test_expired_entry_is_ignored():
    key = latency._latency_cache_key(_dummy_outbound())
    latency._store_latency(key, 5)
    latency._LATENCY_CACHE[key] = (time.monotonic() - latency.LATENCY_CACHE_TTL_OK - 1, 5)
    hit, _value = latency._cached_latency(key)
    assert hit is False


def test_cache_key_ignores_tag():
    first = dict(_dummy_outbound(), tag="one")
    second = dict(_dummy_outbound(), tag="two")
    assert latency._latency_cache_key(first) == latency._latency_cache_key(second)


def test_probe_parallelism_is_capped():
    assert latency.MAX_PROBE_WORKERS <= 8

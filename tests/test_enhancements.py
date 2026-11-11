"""Regression checks for privacy, scoring, routing presets and auto-update logic.

These tests do not require Qt or a live VPN and run in headless CI.
"""
import json
import os
import re
import time

import pytest

from app.config_parser import Profile, RoutingOptions, build_singbox_config
from app.quality import MAX_SAMPLES, QualityTracker, should_switch
from app.route_presets import PRESETS, preset_values
from app.security import atomic_private_json, atomic_private_write, redact, redacted_structure
from app.subscriptions import Subscription, subscription_due


def test_profile_ids_are_distinct_credential_free_and_stable_when_provided():
    a = Profile(name='one', outbound={'type': 'trojan', 'password': 'my-private-password'})
    b = Profile(name='one', outbound={'type': 'trojan', 'password': 'my-private-password'})
    assert a.id != b.id
    assert re.fullmatch(r'[0-9a-f]{32}', a.id)
    assert 'my-private-password' not in a.id
    assert Profile(name='copy', outbound={}, id=a.id).id == a.id


def test_secret_redaction_obfuscates_private_links_uuids_and_nested_fields():
    uuid = '11111111-1111-1111-1111-111111111111'
    original = f'vless://{uuid}@server.example:443?token=secret123#Node'
    result = redact(f'link={original} token=secret123 uuid={uuid}')
    assert uuid not in result and 'secret123' not in result
    structured = redacted_structure({'password': 'pass123', 'nested': [{'api_key': 'foo'}, {'url': original}]})
    assert structured['password'] == '[redacted]'
    assert structured['nested'][0]['api_key'] == '[redacted]'
    assert uuid not in json.dumps(structured)
    assert 'private-data' not in redact('{"password":"private-data"}')


def test_atomic_private_json_updates_atomically(tmp_path):
    file = tmp_path / 'profiles.json'
    atomic_private_json(file, {'profiles': [{'id': 'abc'}]})
    assert json.loads(file.read_text())['profiles'][0]['id'] == 'abc'
    atomic_private_json(file, {'profiles': []})
    assert json.loads(file.read_text())['profiles'] == []
    assert not list(tmp_path.glob('.profiles.json-*'))
    if os.name == 'posix':
        assert file.stat().st_mode & 0o777 == 0o600


def test_atomic_private_write_preserves_old_file_on_failure(tmp_path, monkeypatch):
    import app.security as security
    path = tmp_path / 'settings.ini'
    atomic_private_write(path, 'old')

    def fail_replace(_src, _dst):
        raise OSError('simulated filesystem failure')

    monkeypatch.setattr(security.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='filesystem'):
        atomic_private_write(path, 'new')
    assert path.read_text() == 'old'
    assert not list(tmp_path.glob('.settings.ini-*'))


def test_quality_tracker_records_timeouts_and_bounded_history():
    tracker = QualityTracker()
    for latency in (120, 124, 128, None):
        tracker.record('node-a', latency)
    q = tracker.quality('node-a')
    assert q is not None
    assert q.samples == 4
    assert q.reliability == 0.75
    assert q.jitter_ms == 4
    assert 0 < q.score < 100
    for _ in range(MAX_SAMPLES + 15):
        tracker.record('node-a', 99)
    assert len(tracker.dump()['node-a']) == MAX_SAMPLES
    assert tracker.quality('missing') is None


def test_quality_fallback_and_switch_hysteresis():
    tracker = QualityTracker()
    for i in range(7):
        tracker.record('slow', 600 + i)
        tracker.record('fast', 44 + i)
    a, b = tracker.quality('slow'), tracker.quality('fast')
    assert a and b and b.score > a.score
    assert tracker.best(['slow', 'fast'], [600, 40]) == 1
    assert should_switch(a, b, current_latency=600, candidate_latency=44)
    assert not should_switch(b, a, current_latency=44, candidate_latency=600)
    assert not should_switch(a, b, current_latency=600, candidate_latency=None)
    assert not should_switch(None, None, current_latency=80, candidate_latency=60)
    assert QualityTracker({'bad': [True, 'no', -5, 50]}).dump()['bad'] == [None, None, None, 50]
    assert QualityTracker(['malformed', 'settings']).dump() == {}


@pytest.mark.parametrize('key', list(PRESETS))
def test_preset_configuration_is_accepted(key):
    mode, ru, domains = preset_values(key)
    assert mode in {'all', 'only_selected', 'all_except_selected'}
    assert isinstance(ru, bool)
    assert isinstance(domains, str)
    assert 'youtube.com' in domains if key == 'video' else True


def test_unknown_preset_rejected():
    with pytest.raises(ValueError, match='Unknown'):
        preset_values('nonexistent')


def test_tun_auto_redirect_explicit_opt_in():
    outbound = {'type': 'socks', 'tag': 'proxy', 'server': '127.0.0.1', 'server_port': 8080}
    regular = build_singbox_config(outbound, RoutingOptions())
    enhanced = build_singbox_config(outbound, RoutingOptions(auto_redirect=True))
    assert 'auto_redirect' not in regular['inbounds'][0]
    assert enhanced['inbounds'][0]['auto_redirect'] is True


def test_subscription_updates_respect_individual_opt_in_and_interval():
    now = time.time()
    sub = Subscription(id='one', name='One', url='https://provider.test/sub', updated_at=now - 3 * 3600)
    assert not subscription_due(sub, now, interval_hours=6)
    assert subscription_due(sub, now, interval_hours=2)
    sub.auto_update = False
    assert not subscription_due(sub, now + 10 * 24 * 3600)
    sub.auto_update = True
    sub.updated_at = 0.0
    assert subscription_due(sub, now, interval_hours=100)


def test_disconnected_diagnostics_never_sends_probe(monkeypatch):
    from app.diagnostics import connected_diagnostics
    import app.net_session
    import app.latency
    monkeypatch.setattr(app.net_session, 'interface_exists', lambda _iface: False)
    monkeypatch.setattr(app.latency, 'probe_active_connection',
                        lambda **_kw: pytest.fail('network probe must not run'))
    result = connected_diagnostics(connected=False, interface='ambox')
    assert not result['interface_up']
    assert result['external_ip'] is None
    assert 'no network probe' in result['message']

import pytest
from PySide6.QtCore import QProcess

from app.config_parser import Profile


@pytest.fixture
def vpn(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr("app.net_session.reconcile_stale_session", lambda: None)
    from app.vpn_manager import VpnManager

    manager = VpnManager()
    yield manager


def _profile():
    return Profile(
        name="test",
        outbound={"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1080},
    )


def test_parse_singbox_version():
    from app.vpn_manager import parse_singbox_version

    assert parse_singbox_version("sing-box version 1.14.0\n\nEnvironment: go1.26.7") == (1, 14, 0)
    assert parse_singbox_version("sing-box version 1.8.0-beta.1") == (1, 8, 0)
    assert parse_singbox_version("") is None
    assert parse_singbox_version("garbage output") is None


def test_request_disconnect_on_idle_manager(vpn):
    vpn.request_disconnect()
    assert vpn.status == "disconnected"


def _defer_preflight(monkeypatch, vpn):
    """Deterministic tests for the hand-off: no worker or real sing-box needed."""
    monkeypatch.setattr(vpn, '_resolve_singbox', lambda: '/usr/bin/sing-box')
    monkeypatch.setattr(vpn, 'singbox_version', lambda: (1, 14, 0))

    class DeferredWorker:
        def __init__(self, *, target, args, daemon):
            self.target = target
            self.args = args

        def start(self):
            pass

    monkeypatch.setattr('app.vpn_manager.threading.Thread', DeferredWorker)


def test_switch_preflight_preserves_active_connection_on_error(monkeypatch, vpn):
    _defer_preflight(monkeypatch, vpn)
    vpn._set_status('connected')
    monkeypatch.setattr(vpn.process, 'state', lambda: QProcess.ProcessState.Running)
    profile = _profile()
    vpn.connect_profile(profile)
    assert vpn._pending_connect == (profile, None)
    assert vpn.status == 'connected'  # no stop until validation finishes
    generation = vpn._connect_generation
    vpn._on_prepared(generation, None, 'broken config', profile)
    assert vpn.status == 'connected'
    assert vpn._pending_connect is None
    assert vpn._pending_validated is None


def test_explicit_stop_cancels_switch_preflight(monkeypatch, vpn):
    _defer_preflight(monkeypatch, vpn)
    vpn._set_status('connected')
    monkeypatch.setattr(vpn.process, 'state', lambda: QProcess.ProcessState.Running)
    monkeypatch.setattr('app.vpn_manager.QTimer.singleShot', lambda *args: None)
    vpn.connect_profile(_profile())
    generation = vpn._connect_generation
    assert vpn._pending_connect is not None
    vpn.request_disconnect()
    assert vpn._pending_connect is None
    assert vpn._pending_validated is None
    assert vpn._preparing_switch is None
    assert vpn._connect_generation > generation


def test_validated_switch_starts_after_old_session_finishes(monkeypatch, vpn):
    _defer_preflight(monkeypatch, vpn)
    vpn._set_status('connected')
    monkeypatch.setattr(vpn.process, 'state', lambda: QProcess.ProcessState.Running)
    monkeypatch.setattr('app.vpn_manager.QTimer.singleShot', lambda *args: None)
    profile = _profile()
    vpn.connect_profile(profile)
    checked_config = {'inbounds': [], 'outbounds': []}
    vpn._on_prepared(vpn._connect_generation, checked_config, '/usr/bin/sing-box', profile)
    assert vpn.status == 'disconnecting'
    assert vpn._pending_validated == (checked_config, '/usr/bin/sing-box', profile)

    started = []
    monkeypatch.setattr(vpn, '_launch_prepared', lambda *args: started.append(args))
    monkeypatch.setattr(vpn.process, 'state', lambda: QProcess.ProcessState.NotRunning)
    vpn._on_finished()
    assert started == [(checked_config, '/usr/bin/sing-box', profile)]


def test_singbox_version_is_cached(vpn):
    first = vpn.singbox_version()
    assert first is None or (
        isinstance(first, tuple) and len(first) == 3 and all(isinstance(n, int) for n in first)
    )
    assert vpn._version_checked is True
    assert vpn.singbox_version() == first


def test_old_version_produces_warning(monkeypatch, vpn):
    monkeypatch.setattr(vpn, "_resolve_singbox", lambda: "/usr/bin/sing-box")
    monkeypatch.setattr(vpn, "singbox_version", lambda: (1, 5, 0))
    warnings = vpn.environment_warnings()
    assert any("1.5.0" in w and "minimum" in w for w in warnings)


def test_new_version_produces_no_warning(monkeypatch, vpn):
    monkeypatch.setattr(vpn, "_resolve_singbox", lambda: "/usr/bin/sing-box")
    monkeypatch.setattr(vpn, "singbox_version", lambda: (1, 14, 0))
    warnings = vpn.environment_warnings()
    assert not any("minimum supported" in w for w in warnings)


def test_custom_dns_parser_accepts_bare_ipv6_and_rejects_bad_ports(vpn):
    assert vpn._parse_custom_dns_target("2001:4860:4860::8888") == (
        "udp",
        "2001:4860:4860::8888",
        53,
    )
    assert vpn._parse_custom_dns_target("tcp://[2001:4860:4860::8888]:5353") == (
        "tcp",
        "2001:4860:4860::8888",
        5353,
    )
    assert vpn._parse_custom_dns_target("udp://2001:4860:4860::8888") == (
        "udp",
        "2001:4860:4860::8888",
        53,
    )
    with pytest.raises(ValueError, match="port"):
        vpn._parse_custom_dns_target("dns.google:99999")


def test_custom_dns_probe_tries_all_resolved_addresses(monkeypatch, vpn):
    monkeypatch.setattr(
        vpn,
        "_resolve_dns_target",
        lambda host, port, socktype: [
            (2, ("192.0.2.1", port), "192.0.2.1"),
            (10, ("2001:db8::1", port, 0, 0), "2001:db8::1"),
        ],
    )
    attempts = []

    def probe(scheme, family, sockaddr):
        attempts.append((family, sockaddr))
        if family == 2:
            raise OSError("unreachable")

    monkeypatch.setattr(vpn, "_probe_dns_server", probe)
    assert vpn._prepare_custom_dns("dns.example") == "udp://[2001:db8::1]:53"
    assert len(attempts) == 2


def test_preflight_checks_real_private_config_and_removes_tempfile(monkeypatch, vpn):
    import json
    import os
    import subprocess
    from pathlib import Path

    seen = []

    def simulate_check(argv, **kwargs):
        assert argv[0] == '/usr/bin/sing-box'
        assert argv[1:3] == ['check', '-c']
        path = Path(argv[3])
        assert path.exists()
        if os.name == 'posix':
            assert path.stat().st_mode & 0o777 == 0o600
        assert json.loads(path.read_text()) == {'password': 'private'}
        seen.append(path)
        return subprocess.CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr('app.vpn_manager.subprocess.run', simulate_check)
    vpn.validate_config('/usr/bin/sing-box', {'password': 'private'})
    assert len(seen) == 1 and not seen[0].exists()


def test_preflight_error_redacts_credentials_and_cleans_tempfile(monkeypatch, vpn):
    import subprocess
    from pathlib import Path
    seen = []

    def simulate_failure(argv, **kwargs):
        seen.append(Path(argv[3]))
        return subprocess.CompletedProcess(argv, 1, '', 'ERROR password=do-not-share')

    monkeypatch.setattr('app.vpn_manager.subprocess.run', simulate_failure)
    with pytest.raises(ValueError, match='rejected') as exc:
        vpn.validate_config('/usr/bin/sing-box', {'password': 'do-not-share'})
    assert 'do-not-share' not in str(exc.value)
    assert seen and not seen[0].exists()

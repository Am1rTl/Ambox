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


def test_connect_queues_switch_when_busy(monkeypatch, vpn):
    monkeypatch.setattr(vpn.process, "state", lambda: QProcess.ProcessState.Running)
    monkeypatch.setattr("app.vpn_manager.QTimer.singleShot", lambda *args: None)
    profile = _profile()
    vpn.connect_profile(profile)
    assert vpn._pending_connect == (profile, None)
    assert vpn.status == "disconnecting"


def test_explicit_stop_cancels_queued_switch(monkeypatch, vpn):
    monkeypatch.setattr(vpn.process, "state", lambda: QProcess.ProcessState.Running)
    monkeypatch.setattr("app.vpn_manager.QTimer.singleShot", lambda *args: None)
    vpn.connect_profile(_profile())
    assert vpn._pending_connect is not None
    vpn.request_disconnect()
    assert vpn._pending_connect is None


def test_pending_switch_starts_when_session_finishes(monkeypatch, vpn):
    monkeypatch.setattr(vpn.process, "state", lambda: QProcess.ProcessState.Running)
    monkeypatch.setattr("app.vpn_manager.QTimer.singleShot", lambda *args: None)
    profile = _profile()
    vpn.connect_profile(profile)

    started = []
    monkeypatch.setattr(vpn, "connect_profile", lambda p, r=None: started.append((p, r)))
    monkeypatch.setattr(vpn.process, "state", lambda: QProcess.ProcessState.NotRunning)
    vpn._on_finished()
    assert started == [(profile, None)]


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

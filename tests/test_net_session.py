import json

from app import net_session as ns
from app.config_parser import build_singbox_config


def test_tun_inbound_uses_unique_namespace():
    cfg = build_singbox_config({"type": "direct", "tag": "proxy"}, None)
    tun = cfg["inbounds"][0]
    assert tun["interface_name"] == ns.IFACE_NAME != "tun0"
    assert tun["iproute2_table_index"] == ns.ROUTE_TABLE != 2022
    assert tun["iproute2_rule_index"] == ns.RULE_INDEX
    assert not set(range(9000, 9011)) & set(ns.RULE_RANGE)


def test_journal_roundtrip(tmp_path):
    p = tmp_path / "j.json"
    s = ns.NetSession.new(tmp_path / "cfg.json")
    ns.write_journal(s, p)
    loaded = ns.read_journal(p)
    assert loaded.session_id == s.session_id and loaded.ip_rules == s.ip_rules
    ns.clear_journal(p)
    assert ns.read_journal(p) is None


def test_session_singbox_requires_matching_cmdline(monkeypatch, tmp_path):
    s = ns.NetSession.new(tmp_path / "cfg.json")
    s.singbox_starttime = 5
    monkeypatch.setattr(ns, "proc_starttime", lambda pid: 5)
    monkeypatch.setattr(ns, "proc_cmdline", lambda pid: ["sing-box", "run", "-c", s.config_path])
    assert ns.is_session_singbox(s, 42)
    monkeypatch.setattr(ns, "proc_cmdline", lambda pid: ["sing-box", "run", "-c", "/opt/happ/x.json"])
    assert not ns.is_session_singbox(s, 42)
    monkeypatch.setattr(ns, "proc_starttime", lambda pid: 6)  # pid reuse
    monkeypatch.setattr(ns, "proc_cmdline", lambda pid: ["sing-box", "-c", s.config_path])
    assert not ns.is_session_singbox(s, 42)


def test_cleanup_only_deletes_owned_rules(monkeypatch, tmp_path):
    calls = []

    class R:
        def __init__(self, out="", rc=0):
            self.stdout, self.stderr, self.returncode = out, "", rc

    rules = (
        "0:\tfrom all lookup local\n"
        "9000:\tfrom all to 172.18.0.0/30 lookup 2022\n"
        "9100:\tfrom all lookup 2090 suppress_prefixlength 0\n"
        "9110:\tfrom all nop\n"
        "9105:\tfrom all lookup 2022\n"
        "32766:\tfrom all lookup main\n"
    )

    def fake_run(args, timeout=5.0):
        calls.append(args)
        if args[2:4] == ["rule", "show"]:
            return R(rules)
        return R("")

    monkeypatch.setattr(ns, "_run", fake_run)
    monkeypatch.setattr(ns, "interface_exists", lambda n: False)
    s = ns.NetSession.new(tmp_path / "c.json")
    assert ns.remove_owned_leftovers(s) == []
    deleted = {a[-1] for a in calls if a[2:4] == ["rule", "del"]}
    assert deleted == {"9100", "9110"}
    assert not any("2022" in " ".join(a) for a in calls if "del" in a or "flush" in a)


def test_diff_snapshots():
    before = {"links": ["lo"], "rules": ["a"], "routes": []}
    after = {"links": ["lo", "x"], "rules": ["a"], "routes": []}
    assert ns.diff_snapshots(before, after) == {"links": {"added": ["x"], "removed": []}}


def test_is_own_rule_recognises_singbox_rules_without_iface_name():
    assert ns.is_own_rule("9100:\tfrom all lookup 2090 suppress_prefixlength 0")
    assert ns.is_own_rule("9101:\tfrom all lookup main suppress_prefixlength 0")
    assert ns.is_own_rule("9102:\tnot from all goto 9110")
    assert ns.is_own_rule("9110:\tfrom all nop")
    assert not ns.is_own_rule("9105:\tfrom all lookup 2022")
    assert not ns.is_own_rule("9000:\tfrom all lookup 2090")


def test_own_leftover_rule_is_not_reported_as_foreign_vpn(monkeypatch):
    monkeypatch.setattr(ns, "find_singbox_pids", lambda: [])
    monkeypatch.setattr(ns, "foreign_default_tun", lambda: [])
    monkeypatch.setattr(ns, "_ip_lines", lambda *a: ["9100:\tfrom all lookup 2090"])
    assert ns.detect_foreign_vpn(set()) is None
    monkeypatch.setattr(ns, "_ip_lines", lambda *a: ["9100:\tfrom all lookup 2022"])
    assert "occupied" in ns.detect_foreign_vpn(set())


def test_tools_helpers_are_not_reported_as_foreign_vpn(monkeypatch):
    """`sing-box tools ...` (latency probes) must not block connecting."""
    procs = {
        "101": ("sing-box", ["sing-box", "tools", "fetch",
                             "https://cloudflare.com/cdn-cgi/trace", "-c", "/dev/stdin", "-o", "x"]),
        "102": ("sing-box", ["sing-box", "run", "-c", "/home/u/.ambox/active-config.json"]),
        "103": ("python", ["python", "main.py"]),
    }

    class FakePath:
        def __init__(self, *parts):
            self._p = "/".join(parts)

        def _pid(self):
            return self._p.split("/")[2]

        def read_text(self, encoding="utf-8"):
            return procs[self._pid()][0] + "\n"

        def read_bytes(self):
            return "\0".join(procs[self._pid()][1]).encode() + b"\0"

    monkeypatch.setattr(ns.os, "listdir", lambda p: list(procs))
    monkeypatch.setattr(ns, "Path", FakePath)
    monkeypatch.setattr(ns, "foreign_default_tun", lambda: [])
    monkeypatch.setattr(ns, "_ip_lines", lambda *a: [])

    assert ns.find_singbox_pids() == [102]
    assert "102" in (ns.detect_foreign_vpn(set()) or "")
    assert ns.detect_foreign_vpn({102}) is None

    del procs["102"]  # only a latency probe left: nothing foreign
    assert ns.find_singbox_pids() == []
    assert ns.detect_foreign_vpn(set()) is None


def test_reused_owner_pid_is_not_alive(monkeypatch, tmp_path):
    s = ns.NetSession.new(tmp_path / "c.json")
    s.owner_starttime = 100
    monkeypatch.setattr(ns, "proc_starttime", lambda pid: 200)
    assert not s.owner_alive()
    monkeypatch.setattr(ns, "proc_starttime", lambda pid: 100)
    assert s.owner_alive()

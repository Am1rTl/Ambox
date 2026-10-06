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

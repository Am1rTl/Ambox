"""Ownership-aware network session tracking.

The client itself only starts sing-box (``auto_route`` creates the TUN, ip rules,
routing table and firewall hooks). Everything it creates lives under a unique
namespace (interface, routing table, rule priorities) so that it never collides
with other VPN clients such as Happ (table 2022, rules 9000-9010), and so that
leftovers can be identified and removed without touching foreign state.

A journal is written before sing-box starts, which allows recovery after a GUI
crash / SIGKILL / reboot.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.app_paths import active_config_path, ensure_app_data_dir, ensure_user_owned

IFACE_NAME = "ambox0"
ROUTE_TABLE = 2090
RULE_INDEX = 9100  # sing-box uses RULE_INDEX .. RULE_INDEX + 10
RULE_RANGE = range(RULE_INDEX, RULE_INDEX + 11)
JOURNAL_NAME = "network-session.json"

log = logging.getLogger("net")


def net_log(message: str) -> None:
    logging.info("[NET] %s", message)


def journal_path() -> Path:
    return ensure_app_data_dir() / JOURNAL_NAME


@dataclass
class NetSession:
    session_id: str
    owner_pid: int
    owner_starttime: int = 0
    singbox_pid: int = 0
    singbox_starttime: int = 0
    config_path: str = ""
    interface: str = IFACE_NAME
    routing_tables: list[int] = field(default_factory=lambda: [ROUTE_TABLE])
    ip_rules: list[int] = field(default_factory=lambda: list(RULE_RANGE))
    # Not created by this client directly (sing-box auto_route does it); recorded
    # for completeness. dns/proxy/nft are untouched by the client itself.
    nft_tables: list[str] = field(default_factory=list)
    firewall_rules: list[str] = field(default_factory=list)
    fwmarks: list[str] = field(default_factory=list)
    cgroups: list[str] = field(default_factory=list)
    dns_changes: list[str] = field(default_factory=list)
    system_proxy_changes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @staticmethod
    def new(config_path: Path) -> "NetSession":
        pid = os.getpid()
        return NetSession(
            session_id=uuid.uuid4().hex,
            owner_pid=pid,
            owner_starttime=proc_starttime(pid),
            config_path=str(config_path),
        )

    def owner_alive(self) -> bool:
        if not pid_alive(self.owner_pid):
            return False
        # Old journals have no starttime; otherwise a reused PID must not count as the owner.
        return not self.owner_starttime or proc_starttime(self.owner_pid) == self.owner_starttime


# ---------------------------------------------------------------- journal ---

def write_journal(session: NetSession, path: Path | None = None) -> None:
    path = path or journal_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(session), indent=2), encoding="utf-8")
    os.replace(tmp, path)
    ensure_user_owned(path)


def read_journal(path: Path | None = None) -> NetSession | None:
    path = path or journal_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {k: v for k, v in data.items() if k in NetSession.__dataclass_fields__}
        return NetSession(**known)
    except (OSError, ValueError, TypeError):
        return None


def clear_journal(path: Path | None = None) -> None:
    try:
        (path or journal_path()).unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("[NET] cannot remove journal: %s", exc)


# ------------------------------------------------------------ /proc helpers ---

def proc_starttime(pid: int) -> int:
    """Process start time in clock ticks (guards against PID reuse), 0 if gone."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        return int(stat.rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return 0


def proc_cmdline(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    return [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]


def pid_alive(pid: int) -> bool:
    return pid > 0 and proc_starttime(pid) != 0


def is_session_singbox(session: NetSession, pid: int) -> bool:
    """True only if ``pid`` is really the sing-box instance this session started."""
    if pid <= 0:
        return False
    if session.singbox_starttime and proc_starttime(pid) != session.singbox_starttime:
        return False
    args = proc_cmdline(pid)
    return bool(args) and session.config_path in args


def find_singbox_pids() -> list[int]:
    pids: list[int] = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return pids
    for name in names:
        if not name.isdigit():
            continue
        try:
            comm = Path(f"/proc/{name}/comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if comm == "sing-box":
            pids.append(int(name))
    return pids


# ----------------------------------------------------------- ip inspection ---

def _run(args: list[str], timeout: float = 5.0) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("[NET] command %s failed: %s", args, exc)
        return None


def _ip_lines(*args: str) -> list[str]:
    out: list[str] = []
    for family in ("-4", "-6"):
        res = _run(["ip", family, *args])
        if res is not None and res.returncode == 0:
            out.extend(line.strip() for line in res.stdout.splitlines() if line.strip())
    return out


_RULE_PREF = re.compile(r"^(\d+):")


def _rule_pref(line: str) -> int:
    m = _RULE_PREF.match(line)
    return int(m.group(1)) if m else -1


def is_own_rule(line: str) -> bool:
    """A rule in our priority range that only refers to our table / builtin tables / our range.

    sing-box rules carry no interface name (``lookup 2090``, ``lookup main suppress_prefixlength 0``,
    ``goto 9110``, ``nop``), so ownership is "nothing in it points at somebody else's table".
    """
    if _rule_pref(line) not in RULE_RANGE:
        return False
    for table in re.findall(r"\blookup (\S+)", line):
        if table not in _OWN_OR_BUILTIN_TABLES:
            return False
    for target in re.findall(r"\bgoto (\d+)", line):
        if int(target) not in RULE_RANGE:
            return False
    return True


_OWN_OR_BUILTIN_TABLES = {str(ROUTE_TABLE), "main", "local", "default", "253", "254", "255"}


def interface_exists(name: str) -> bool:
    return Path("/sys/class/net", name).exists()


def snapshot() -> dict[str, list[str]]:
    """Global state that must be unchanged by a connect/disconnect cycle."""
    res = _run(["ip", "-o", "link", "show"])
    links = []
    if res is not None and res.returncode == 0:
        for line in res.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                links.append(parts[1].strip().split("@")[0])
    return {
        "links": sorted(links),
        "rules": sorted(_ip_lines("rule", "show")),
        "routes": sorted(_ip_lines("route", "show", "table", "all")),
    }


def foreign_default_tun() -> list[str]:
    """TUN-like interfaces that are not ours and carry a default route."""
    owners: set[str] = set()
    for line in _ip_lines("route", "show", "table", "all"):
        if line.startswith("default"):
            m = re.search(r"\bdev (\S+)", line)
            if m:
                owners.add(m.group(1))
    foreign = []
    for dev in sorted(owners):
        if dev == IFACE_NAME:
            continue
        sysdir = Path("/sys/class/net", dev)
        if (sysdir / "tun_flags").exists() or "wireguard" in _read(sysdir / "uevent"):
            foreign.append(dev)
    return foreign


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def detect_foreign_vpn(own_pids: set[int]) -> str | None:
    """Explain why connecting now would clash with another VPN/TUN client."""
    for pid in find_singbox_pids():
        if pid not in own_pids:
            return (
                "Another VPN/TUN is currently active (sing-box pid "
                f"{pid}). Disable it before connecting."
            )
    foreign = foreign_default_tun()
    if foreign:
        return (
            f"Another VPN/TUN is currently active (interface {', '.join(foreign)}). "
            "Disable it before connecting."
        )
    for line in _ip_lines("rule", "show"):
        if _rule_pref(line) in RULE_RANGE and not is_own_rule(line):
            return (
                f"Policy routing priority {_rule_pref(line)} is occupied by another client. "
                "Disable the other VPN before connecting."
            )
    return None


# ------------------------------------------------------------------ cleanup ---

def _terminate(pid: int, timeout: float = 5.0) -> bool:
    for sig, wait in ((signal.SIGTERM, timeout), (signal.SIGKILL, 2.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return True
        except PermissionError as exc:
            log.warning("[NET] cannot signal pid=%s errno=%s", pid, exc.errno)
            return False
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if not pid_alive(pid):
                return True
            time.sleep(0.1)
    return not pid_alive(pid)


def remove_owned_leftovers(session: NetSession) -> list[str]:
    """Delete only what ``session`` created. Returns resources that could not be removed."""
    failed: list[str] = []

    for family in ("-4", "-6"):
        res = _run(["ip", family, "rule", "show"])
        if res is None or res.returncode != 0:
            continue
        # Several rules can share one priority and `ip rule del pref N` removes one per call.
        owned = [
            _rule_pref(line)
            for line in res.stdout.splitlines()
            if _rule_pref(line) in session.ip_rules and is_own_rule(line)
        ]
        for pref in owned:
            del_res = _run(["ip", family, "rule", "del", "pref", str(pref)])
            if del_res is not None and del_res.returncode == 0:
                net_log(f"removed owned rule pref={pref} ({family})")
            else:
                failed.append(f"ip rule pref={pref}")
                log.warning(
                    "[NET] cannot remove rule pref=%s cmd='ip %s rule del pref %s' rc=%s err=%s owner=%s",
                    pref, family, pref, getattr(del_res, "returncode", None),
                    (del_res.stderr.strip() if del_res else ""), session.session_id,
                )

    for table in session.routing_tables:
        for family in ("-4", "-6"):
            res = _run(["ip", family, "route", "show", "table", str(table)])
            if res is not None and res.returncode == 0 and res.stdout.strip():
                flush = _run(["ip", family, "route", "flush", "table", str(table)])
                if flush is not None and flush.returncode == 0:
                    net_log(f"removed owned routes table={table} ({family})")
                else:
                    failed.append(f"route table {table}")

    if session.interface and interface_exists(session.interface):
        res = _run(["ip", "link", "del", session.interface])
        if res is not None and res.returncode == 0:
            net_log(f"removed owned interface {session.interface}")
        else:
            failed.append(f"interface {session.interface}")
            log.warning(
                "[NET] cannot remove interface %s cmd='ip link del %s' rc=%s err=%s owner=%s",
                session.interface, session.interface, getattr(res, "returncode", None),
                (res.stderr.strip() if res else ""), session.session_id,
            )
    return failed


def _own_leftovers_present() -> bool:
    if interface_exists(IFACE_NAME):
        return True
    if any(is_own_rule(line) for line in _ip_lines("rule", "show")):
        return True
    return bool(_ip_lines("route", "show", "table", str(ROUTE_TABLE)))


def _reconcile_without_journal() -> str | None:
    """Journal lost (deleted, disk error) but our namespace is still populated."""
    if not _own_leftovers_present():
        return None
    # A sing-box still holding our interface may be a live instance of this app; leave it.
    own_config = str(active_config_path())
    for pid in find_singbox_pids():
        if own_config in proc_cmdline(pid):
            return None
    net_log("found leftovers in our namespace without a journal, removing them")
    session = NetSession(session_id="orphan", owner_pid=0, interface=IFACE_NAME)
    session.ip_rules = [
        _rule_pref(line) for line in _ip_lines("rule", "show") if is_own_rule(line)
    ]
    failed = remove_owned_leftovers(session)
    if failed:
        return "Leftovers from a previous VPN session could not be removed: " + ", ".join(failed)
    return None


def reconcile_stale_session() -> str | None:
    """Clean leftovers of a previous session whose owner died. Returns a warning, or None."""
    session = read_journal()
    if session is None:
        return _reconcile_without_journal()

    if session.owner_pid != os.getpid() and session.owner_alive():
        # Another live instance of this app owns the session; do not touch it.
        return None

    net_log(f"found stale session {session.session_id} (owner pid {session.owner_pid} is gone)")
    if is_session_singbox(session, session.singbox_pid):
        net_log(f"stopping orphaned sing-box pid={session.singbox_pid}")
        if not _terminate(session.singbox_pid):
            return f"Could not stop orphaned sing-box (pid {session.singbox_pid}). Stop it manually."
    failed = remove_owned_leftovers(session)
    if failed:
        return (
            "Leftovers from the previous VPN session could not be removed: "
            + ", ".join(failed)
            + ". Run the cleanup with root privileges (e.g. `sudo ip link del "
            f"{session.interface}`)."
        )
    clear_journal()
    return None


def diff_snapshots(before: dict[str, list[str]], after: dict[str, list[str]]) -> dict[str, dict[str, list[str]]]:
    result: dict[str, dict[str, list[str]]] = {}
    for key in before:
        b, a = set(before[key]), set(after.get(key, []))
        added, removed = sorted(a - b), sorted(b - a)
        if added or removed:
            result[key] = {"added": added, "removed": removed}
    return result

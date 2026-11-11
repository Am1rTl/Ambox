import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QObject, QProcess, QTimer, Signal

from app.app_paths import active_config_path, ensure_user_owned, singbox_cache_path
from app.security import atomic_private_json, redact
from app.config_parser import Profile, RoutingOptions, build_singbox_config
from app.latency import find_unavailable_nodes
from app.xray_bundle import ensure_rule_sets, required_rule_sets
from app import net_session

# Generated configs use DNS `local` introduced in sing-box 1.12.0.
# Versions below this floor are rejected *before* stopping a working tunnel.
MIN_SINGBOX_VERSION = (1, 12, 0)


def parse_singbox_version(output: str) -> tuple[int, int, int] | None:
    """Parse the first line of `sing-box version` ("sing-box version 1.14.0")."""
    lines = (output or "").strip().splitlines()
    if not lines:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", lines[0])
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


class VpnManager(QObject):
    status_changed = Signal(str)
    log_line = Signal(str)
    error = Signal(str)
    singbox_availability_changed = Signal(bool)
    install_state_changed = Signal(bool)
    _prepared = Signal(int, object, str, object)
    profile_starting = Signal(object)
    connection_lost = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._on_finished)
        self.install_process = QProcess(self)
        self.install_process.readyReadStandardOutput.connect(self._read_install_stdout)
        self.install_process.readyReadStandardError.connect(self._read_install_stderr)
        self.install_process.finished.connect(self._on_install_finished)
        self._status = "disconnected"
        self._temp_config = active_config_path()
        self._temp_config.parent.mkdir(parents=True, exist_ok=True)
        self._install_log: list[str] = []
        self._fatal_reported = False
        self._session: net_session.NetSession | None = None
        self._net_before: dict[str, list[str]] | None = None
        self._pending_warning = net_session.reconcile_stale_session()
        self._connect_generation = 0
        self._pending_connect: tuple[Profile, RoutingOptions | None] | None = None
        self._pending_validated: tuple[dict, str, Profile] | None = None
        self._preparing_switch: int | None = None
        self._intentional_stop = False
        self._active_session: tuple[dict, str, Profile] | None = None
        self._rollback_session: tuple[dict, str, Profile] | None = None
        self._singbox_version: tuple[int, int, int] | None = None
        self._version_checked = False
        self._prepared.connect(self._on_prepared)

    @property
    def status(self) -> str:
        return self._status

    def _set_status(self, value: str) -> None:
        if self._status != value:
            self._status = value
            self.status_changed.emit(value)

    def _resolve_singbox(self) -> str | None:
        detected = shutil.which("sing-box")
        if detected:
            return detected

        for candidate in (
            "/usr/bin/sing-box",
            "/usr/local/bin/sing-box",
            str(Path.home() / ".local" / "bin" / "sing-box"),
        ):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _strip_ansi(self, text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def _parse_custom_dns_target(self, value: str) -> tuple[str, str, int]:
        raw = value.strip()
        if not raw:
            raise ValueError("Custom DNS server is empty.")

        if "://" in raw:
            scheme, target = raw.split("://", 1)
            scheme = scheme.lower()
            if scheme not in {"udp", "tcp"}:
                raise ValueError("Custom DNS supports only udp:// or tcp:// addresses.")
            try:
                host = str(ip_address(target))
                parsed = None
            except ValueError:
                parsed = urlparse(raw)
                host = parsed.hostname
            if (
                not host
                or (parsed is not None and parsed.path not in {"", "/"})
                or (parsed is not None and parsed.query)
                or (parsed is not None and parsed.fragment)
                or (parsed is not None and parsed.username)
                or (parsed is not None and parsed.password)
            ):
                raise ValueError("Custom DNS address is invalid.")
        else:
            # urlparse treats a bare IPv6 address as a host followed by an
            # invalid port. Recognize it before parsing host:port syntax.
            try:
                host = str(ip_address(raw))
                return "udp", host, 53
            except ValueError:
                parsed = urlparse(f"//{raw}")
                scheme = "udp"
                host = parsed.hostname
            if not host:
                raise ValueError("Custom DNS address is invalid.")

        try:
            port = parsed.port if parsed is not None and parsed.port is not None else 53
        except ValueError as exc:
            raise ValueError("Custom DNS port is invalid.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Custom DNS port is invalid.")
        return scheme, host, port

    def _dns_query_packet(self) -> tuple[bytes, bytes]:
        query_id = os.urandom(2)
        header = query_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"\x07example\x03com\x00"
        question = qname + b"\x00\x01\x00\x01"
        return header + question, query_id

    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            data = sock.recv(remaining)
            if not data:
                raise OSError("connection closed")
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)

    def _resolve_dns_target(self, host: str, port: int, socktype: int) -> list[tuple[int, tuple, str]]:
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socktype)
        except socket.gaierror as exc:
            raise ValueError(
                f"Cannot resolve Custom DNS host '{host}'. Check internet connection or use an IP address."
            ) from exc
        if not infos:
            raise ValueError(f"Cannot resolve Custom DNS host '{host}'.")

        infos = sorted(infos, key=lambda item: 0 if item[0] == socket.AF_INET else 1)
        targets: list[tuple[int, tuple, str]] = []
        seen: set[tuple[int, tuple]] = set()
        for family, _socktype, _proto, _canonname, sockaddr in infos:
            key = (family, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            targets.append((family, sockaddr, sockaddr[0]))
        return targets

    def _probe_dns_server(self, scheme: str, family: int, sockaddr: tuple, timeout: float = 2.0) -> None:
        query, query_id = self._dns_query_packet()
        if scheme == "udp":
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, sockaddr)
                response, _ = sock.recvfrom(2048)
            if len(response) < 12 or response[:2] != query_id or not (response[2] & 0x80):
                raise OSError("invalid dns response")
            return

        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            tcp_query = len(query).to_bytes(2, "big") + query
            sock.sendall(tcp_query)
            length_data = self._recv_exact(sock, 2)
            payload_len = int.from_bytes(length_data, "big")
            response = self._recv_exact(sock, payload_len)
        if len(response) < 12 or response[:2] != query_id or not (response[2] & 0x80):
            raise OSError("invalid dns response")

    def _prepare_custom_dns(self, value: str) -> str:
        scheme, host, port = self._parse_custom_dns_target(value)
        socktype = socket.SOCK_DGRAM if scheme == "udp" else socket.SOCK_STREAM
        targets = self._resolve_dns_target(host, port, socktype)
        last_error: OSError | None = None
        for family, sockaddr, resolved_ip in targets:
            try:
                self._probe_dns_server(scheme, family, sockaddr)
            except OSError as exc:
                last_error = exc
                continue

            try:
                ip_address(resolved_ip)
            except ValueError:
                last_error = OSError(f"invalid resolved address: {resolved_ip}")
                continue

            if ":" in resolved_ip:
                return f"{scheme}://[{resolved_ip}]:{port}"
            return f"{scheme}://{resolved_ip}:{port}"

        raise ValueError(
            f"Custom DNS server '{host}:{port}' is not responding to DNS queries."
        ) from last_error

    def _detect_external_conflict(self) -> str | None:
        warning = net_session.reconcile_stale_session()
        if warning:
            return warning

        own: set[int] = set()
        if self._session is not None and self._session.singbox_pid:
            own.add(self._session.singbox_pid)
        if net_session.interface_exists(net_session.IFACE_NAME) and not own:
            return (
                f"Interface {net_session.IFACE_NAME} already exists and is not owned by a live session. "
                "Stop whatever created it (or remove it with `sudo ip link del "
                f"{net_session.IFACE_NAME}`) and try again."
            )
        return net_session.detect_foreign_vpn(own)

    def take_startup_warning(self) -> str | None:
        warning, self._pending_warning = self._pending_warning, None
        return warning

    def _begin_session(self) -> None:
        self._net_before = net_session.snapshot()
        self._session = net_session.NetSession.new(self._temp_config)
        net_session.write_journal(self._session)
        net_session.net_log(f"session {self._session.session_id} started")

    def _record_singbox_pid(self) -> None:
        if self._session is None:
            return
        pid = int(self.process.processId())
        self._session.singbox_pid = pid
        self._session.singbox_starttime = net_session.proc_starttime(pid)
        net_session.write_journal(self._session)
        net_session.net_log(
            f"sing-box pid={pid} owns interface={self._session.interface} "
            f"table={self._session.routing_tables} rules={self._session.ip_rules[0]}-{self._session.ip_rules[-1]}"
        )

    def _end_session(self) -> None:
        """Remove anything of ours that is left, verify and drop the journal."""
        session, before = self._session, self._net_before
        self._session = self._net_before = None
        if session is None:
            return
        failed = net_session.remove_owned_leftovers(session)
        if not failed:
            net_session.clear_journal()
        else:
            self.log_line.emit("WARNING: could not remove: " + ", ".join(failed))
        if before is not None:
            diff = net_session.diff_snapshots(before, net_session.snapshot())
            if diff:
                logging.warning("[NET] state differs after disconnect: %s", json.dumps(diff))
            else:
                net_session.net_log("system state after disconnect == state before connect")

    def has_singbox(self) -> bool:
        return self._resolve_singbox() is not None

    def singbox_version(self) -> tuple[int, int, int] | None:
        """Cached (major, minor, patch) of the resolved sing-box binary."""
        if self._version_checked:
            return self._singbox_version
        self._version_checked = True
        singbox = self._resolve_singbox()
        if not singbox:
            return None
        try:
            proc = subprocess.run(
                [singbox, "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        self._singbox_version = parse_singbox_version(proc.stdout or proc.stderr)
        return self._singbox_version

    def singbox_has_net_admin(self) -> bool | None:
        """Inspect actual file capabilities using getcap (setcap -v is not a query)."""
        singbox = self._resolve_singbox()
        if not singbox:
            return None
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            return True
        getcap_path = shutil.which('getcap')
        if not getcap_path:
            return None
        try:
            result = subprocess.run([getcap_path, singbox], capture_output=True,
                                    text=True, timeout=4, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        output = (result.stdout + result.stderr).lower()
        # `cap_net_admin=ep`, `cap_net_admin+ep`, possibly combined with other caps.
        return bool(re.search(r'\bcap_net_admin\b[^\n]*[=+]\s*(?:[a-z,]*e[a-z,]*p|[a-z,]*p[a-z,]*e)', output))

    def validate_config(self, singbox: str, config: dict) -> None:
        """Validate the real generated JSON before changing the current tunnel."""
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.json',
                                             prefix='.ambox-check-',
                                             dir=str(self._temp_config.parent),
                                             delete=False) as temp:
                tmp_name = temp.name
                if os.name == 'posix':
                    os.fchmod(temp.fileno(), 0o600)
                json.dump(config, temp, ensure_ascii=False)
            result = subprocess.run([singbox, 'check', '-c', tmp_name],
                                    capture_output=True, text=True, timeout=20,
                                    check=False)
            if result.returncode != 0:
                detail = redact((result.stderr or result.stdout or 'unknown error').strip())[-1500:]
                raise ValueError(f'sing-box rejected the generated configuration: {detail}')
        except subprocess.TimeoutExpired as exc:
            raise ValueError('sing-box configuration check timed out (20 s).') from exc
        except OSError as exc:
            raise ValueError(f'Cannot validate sing-box config: {exc}') from exc
        finally:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    def environment_warnings(self) -> list[str]:
        warnings: list[str] = []
        singbox = self._resolve_singbox()
        if not singbox:
            warnings.append("sing-box executable was not found in PATH or common install locations.")
        else:
            version = self.singbox_version()
            if version is not None and version < MIN_SINGBOX_VERSION:
                minimum = ".".join(map(str, MIN_SINGBOX_VERSION))
                found = ".".join(map(str, version))
                warnings.append(
                    f"sing-box {found} is older than the minimum supported {minimum}. "
                    "Please upgrade sing-box."
                )
        if shutil.which("ip") is None:
            warnings.append("The `ip` command is missing. Interface checks may be incomplete.")
        if shutil.which("pgrep") is None:
            warnings.append("The `pgrep` command is missing. External sing-box conflict checks may be incomplete.")
        if singbox:
            has_cap = self.singbox_has_net_admin()
            if has_cap is False:
                warnings.append(
                    "sing-box does not have CAP_NET_ADMIN. If TUN setup fails, run: "
                    'sudo setcap cap_net_admin+ep "$(command -v sing-box)"'
                )
            elif has_cap is None:
                warnings.append("Cannot verify sing-box capabilities; install `getcap` (libcap2-bin) to inspect TUN permissions.")
        return warnings

    def refresh_singbox_availability(self) -> None:
        self.singbox_availability_changed.emit(self.has_singbox())

    def _detect_install_command(self) -> str | None:
        if shutil.which("apt-get"):
            return (
                "mkdir -p /etc/apt/keyrings && "
                "curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc && "
                "chmod a+r /etc/apt/keyrings/sagernet.asc && "
                "cat > /etc/apt/sources.list.d/sagernet.sources <<'EOF'\n"
                "Types: deb\n"
                "URIs: https://deb.sagernet.org/\n"
                "Suites: *\n"
                "Components: *\n"
                "Enabled: yes\n"
                "Signed-By: /etc/apt/keyrings/sagernet.asc\n"
                "EOF\n"
                "apt-get update && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y sing-box || "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y sing-box-beta"
            )
        if shutil.which("dnf"):
            return "dnf install -y sing-box"
        if shutil.which("pacman"):
            return "pacman -Sy --noconfirm sing-box"
        if shutil.which("zypper"):
            return "zypper --non-interactive install sing-box"
        if shutil.which("apk"):
            return "apk add sing-box"
        return None

    def install_singbox(self) -> None:
        if self.install_process.state() != QProcess.NotRunning:
            self.error.emit("Installer is already running")
            return
        if self.has_singbox():
            self.log_line.emit("sing-box is already installed")
            self.refresh_singbox_availability()
            return

        pkexec = shutil.which("pkexec")
        if not pkexec:
            self.error.emit("pkexec not found. Install PolicyKit or install sing-box manually.")
            return

        install_cmd = self._detect_install_command()
        if not install_cmd:
            self.error.emit("Unsupported Linux package manager. Please install sing-box manually.")
            return

        cmd = (
            "set -e; "
            f"{install_cmd}; "
            "if command -v setcap >/dev/null 2>&1 && command -v sing-box >/dev/null 2>&1; then "
            "setcap cap_net_admin+ep \"$(command -v sing-box)\" || true; "
            "fi"
        )
        self._install_log.clear()
        self.log_line.emit("Launching installer via pkexec...")
        self.install_state_changed.emit(True)
        self.install_process.start(pkexec, ["sh", "-lc", cmd])
        if not self.install_process.waitForStarted(4000):
            self.install_state_changed.emit(False)
            self.error.emit("Failed to start installer process")
            return

    def connect_profile(self, profile: Profile, routing: RoutingOptions | None = None) -> None:
        if self._status == 'disconnecting':
            self._pending_connect = (profile, routing)
            return
        singbox = self._resolve_singbox()
        if not singbox:
            self.error.emit('sing-box not found. Click "Install sing-box".')
            self.refresh_singbox_availability()
            return
        version = self.singbox_version()
        if version is not None and version < MIN_SINGBOX_VERSION:
            minimum = '.'.join(map(str, MIN_SINGBOX_VERSION))
            self.error.emit(f'sing-box {version[0]}.{version[1]}.{version[2]} is too old; {minimum}+ is required.')
            return
        busy = self.process.state() != QProcess.NotRunning
        if not busy and self._status != 'connecting':
            conflict = self._detect_external_conflict()
            if conflict:
                self.error.emit(conflict)
                return
        self._connect_generation += 1
        generation = self._connect_generation
        self._pending_validated = None
        if busy:
            # Keep the original tunnel alive while the replacement is fetched,
            # generated and validated; old connection is untouched on error.
            self._pending_connect = (profile, routing)
            self._preparing_switch = generation
            self.log_line.emit(f'Preflight for {profile.name} (existing VPN stays connected)...')
        else:
            self._pending_connect = None
            self._preparing_switch = None
            self._set_status('connecting')
            self.log_line.emit(f'Preparing profile: {profile.name}')
        threading.Thread(target=self._prepare_worker,
                         args=(generation, profile, routing, singbox), daemon=True).start()

    def _prepare_worker(self, generation: int, profile: Profile,
                        routing: RoutingOptions | None, singbox: str) -> None:
        try:
            # Do not mutate persisted routing options in a background thread.
            if routing and routing.dns_mode == 'custom':
                from dataclasses import replace
                dns = self._prepare_custom_dns(routing.custom_dns)
                routing = replace(routing, custom_dns=dns)
                self.log_line.emit('Custom DNS preflight passed')
            unavailable: set[str] = set()
            if profile.xray:
                ensure_rule_sets(required_rule_sets(profile.xray))
                unavailable = find_unavailable_nodes(profile.xray)
            cfg = build_singbox_config(profile.outbound, routing, xray=profile.xray, unavailable=unavailable)
            if profile.xray:
                nodes = [ob for ob in cfg['outbounds'] if ob.get('type') not in {'direct', 'block', 'urltest'}]
                groups = sum(1 for ob in cfg['outbounds'] if ob.get('type') == 'urltest')
                self.log_line.emit(
                    f'Happ config: {len(nodes)} reachable node(s), '
                    f'{len(unavailable)} skipped, {groups} balancer(s)'
                )
            self.validate_config(singbox, cfg)
        except Exception as exc:
            self._prepared.emit(generation, None, redact(str(exc)), profile)
            return
        self._prepared.emit(generation, cfg, singbox, profile)

    def _on_prepared(self, generation: int, cfg: object, info: str, profile: Profile) -> None:
        if generation != self._connect_generation:
            return  # superseded or cancelled during preparation
        switching = generation == self._preparing_switch
        if not isinstance(cfg, dict):
            if switching:
                self._preparing_switch = None
                self._pending_connect = None
                self.error.emit(f'Profile switch cancelled; existing VPN unchanged. {info}')
            elif self._status == 'connecting':
                self._set_status('disconnected')
                self.error.emit(info or 'Failed to prepare VPN configuration')
                self.connection_lost.emit('VPN preflight failed')
            return
        if switching and self.process.state() != QProcess.NotRunning:
            self._preparing_switch = None
            self._rollback_session = self._active_session if self._status == 'connected' else None
            self._pending_validated = (cfg, info, profile)
            self.log_line.emit('New configuration checked. Switching VPN session...')
            self.request_disconnect(cancel_pending=False)
            return
        if self._status not in {'connecting', 'connected'}:
            return
        self._preparing_switch = None
        self._pending_connect = None
        self._set_status('connecting')
        self._launch_prepared(cfg, info, profile)

    def _launch_prepared(self, cfg: dict, singbox: str, profile: Profile) -> None:
        try:
            atomic_private_json(self._temp_config, cfg)
            ensure_user_owned(self._temp_config)
            self._fatal_reported = False
            self._begin_session()
        except OSError as exc:
            self._set_status('disconnected')
            self.error.emit(f'Could not prepare VPN session: {exc}')
            self._try_rollback()
            return
        self.log_line.emit(f'Using sing-box: {singbox}')
        program, args = singbox, ['run', '-c', str(self._temp_config)]
        setpriv = shutil.which('setpriv')
        if setpriv:
            program, args = setpriv, ['--pdeathsig', 'TERM', '--', singbox, *args]
        self._intentional_stop = False
        self.process.start(program, args)
        if not self.process.waitForStarted(4000):
            self._set_status('disconnected')
            self._end_session()
            self.error.emit('Failed to start sing-box')
            self._try_rollback()
            return
        self._active_session = (cfg, singbox, profile)
        self._record_singbox_pid()
        self.profile_starting.emit(profile)

    def _try_rollback(self) -> bool:
        rollback, self._rollback_session = self._rollback_session, None
        if rollback is None:
            return False
        self.log_line.emit('New VPN failed to start. Attempting to restore the previous configuration...')
        self._set_status('connecting')
        self._launch_prepared(*rollback)
        return True

    def request_disconnect(self, cancel_pending: bool = True) -> None:
        """Stop the VPN without blocking the GUI thread.

        SIGTERM is sent immediately; if sing-box is still alive after 8s it is
        SIGKILLed via a timer. Cleanup happens in _on_finished, which also
        picks up a queued profile switch (see connect_profile).
        """
        self._connect_generation += 1
        generation = self._connect_generation
        if cancel_pending:
            self._pending_connect = None
            self._pending_validated = None
            self._preparing_switch = None
            self._rollback_session = None
        self._intentional_stop = True
        if self.process.state() == QProcess.NotRunning:
            self._end_session()
            self._set_status("disconnected")
            self._start_pending_connect()
            return

        self._set_status("disconnecting")
        # SIGTERM lets sing-box remove its own routes/rules/TUN; only escalate after a generous wait.
        self.process.terminate()
        QTimer.singleShot(8000, lambda: self._escalate_disconnect(generation))

    def _escalate_disconnect(self, generation: int) -> None:
        if generation != self._connect_generation or self._status != "disconnecting":
            return  # already finished or superseded by a new connect
        if self.process.state() == QProcess.NotRunning:
            return  # _on_finished is on its way
        net_session.net_log("sing-box ignored SIGTERM, sending SIGKILL")
        self.process.kill()

    def _start_pending_connect(self) -> None:
        prepared, self._pending_validated = self._pending_validated, None
        if prepared is not None and self._status == 'disconnected':
            self._pending_connect = None
            self._set_status('connecting')
            self._launch_prepared(*prepared)
            return
        pending, self._pending_connect = self._pending_connect, None
        if pending is not None and self._status == 'disconnected':
            profile, routing = pending
            self.connect_profile(profile, routing)

    def disconnect(self) -> None:
        """Synchronous stop for application shutdown (closeEvent/aboutToQuit).

        UI-initiated stops must use request_disconnect() instead: this blocks
        the calling thread for up to ~10s.
        """
        self._connect_generation += 1
        self._pending_connect = None
        self._pending_validated = None
        self._preparing_switch = None
        self._rollback_session = None
        self._intentional_stop = True
        if self.process.state() == QProcess.NotRunning:
            self._end_session()
            self._set_status("disconnected")
            return

        self._set_status("disconnecting")
        self.process.terminate()
        if not self.process.waitForFinished(8000):
            net_session.net_log("sing-box ignored SIGTERM, sending SIGKILL")
            self.process.kill()
            self.process.waitForFinished(2000)
        self._end_session()
        self._set_status("disconnected")
        ensure_user_owned(singbox_cache_path())
        self.log_line.emit("VPN disconnected")

    def _read_stdout(self) -> None:
        output = self._strip_ansi(bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace"))
        for line in output.splitlines():
            self.log_line.emit(line)
            if self._status == "connecting" and "sing-box started" in line.lower():
                self._rollback_session = None
                self._set_status("connected")

    def _read_stderr(self) -> None:
        output = self._strip_ansi(bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace"))
        for line in output.splitlines():
            self.log_line.emit(line)
            if self._status == "connecting" and "sing-box started" in line.lower():
                self._rollback_session = None
                self._set_status("connected")
            if not self._fatal_reported and "FATAL" in line:
                self._fatal_reported = True
                if "unknown transport type" in line:
                    self.error.emit(
                        "Profile format is incompatible with current sing-box transport settings. "
                        "Try reimporting the link."
                    )
                elif "configure tun interface: operation not permitted" in line.lower() or "operation not permitted" in line.lower():
                    self.error.emit(
                        "sing-box has no permission to create the TUN interface. "
                        "Run: sudo setcap cap_net_admin+ep \"$(command -v sing-box)\" and reconnect."
                    )
                elif "address already in use" in line:
                    self.error.emit("VPN interface/port is already in use by another process.")
                else:
                    self.error.emit("sing-box failed to start. Check detailed logs below.")

    def _on_finished(self) -> None:
        unexpected = not self._intentional_stop and self._pending_validated is None
        was_starting = self._status == 'connecting'
        self._end_session()
        if unexpected and was_starting and self._try_rollback():
            return
        if unexpected:
            self._rollback_session = None
        if self._status != 'disconnected':
            self._set_status('disconnected')
            ensure_user_owned(singbox_cache_path())
            self.log_line.emit('sing-box process exited')
        self._start_pending_connect()
        if unexpected:
            self.connection_lost.emit('sing-box exited unexpectedly')

    def _read_install_stdout(self) -> None:
        output = self._strip_ansi(
            bytes(self.install_process.readAllStandardOutput()).decode("utf-8", errors="replace")
        )
        for line in output.splitlines():
            self._install_log.append(line)
            self.log_line.emit(f"[installer] {line}")

    def _read_install_stderr(self) -> None:
        output = self._strip_ansi(
            bytes(self.install_process.readAllStandardError()).decode("utf-8", errors="replace")
        )
        for line in output.splitlines():
            self._install_log.append(line)
            self.log_line.emit(f"[installer] {line}")

    def _on_install_finished(self, exit_code: int, exit_status) -> None:
        self.install_state_changed.emit(False)
        ok = exit_status == QProcess.NormalExit and exit_code == 0 and self.has_singbox()
        if ok:
            self.log_line.emit("sing-box installed successfully")
        else:
            log_text = "\n".join(self._install_log).lower()
            if "unable to locate package sing-box" in log_text:
                self.error.emit(
                    "Package sing-box/sing-box-beta was not found even after adding SagerNet repo."
                )
            elif "not signed" in log_text or "openpgp signature verification failed" in log_text:
                self.error.emit(
                    "APT repo signature error detected. Fix/disable broken third-party repos and retry installation."
                )
            elif "could not resolve" in log_text or "temporary failure resolving" in log_text:
                self.error.emit("Network/DNS error while installing sing-box. Check internet and retry.")
            else:
                self.error.emit("sing-box installation failed or was cancelled")
        self._singbox_version = None
        self._version_checked = False
        self.refresh_singbox_availability()

import json
import os
import re
import shutil
import socket
import subprocess
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QObject, QProcess, Signal

from app.app_paths import active_config_path
from app.config_parser import Profile, RoutingOptions, build_singbox_config


class VpnManager(QObject):
    status_changed = Signal(str)
    log_line = Signal(str)
    error = Signal(str)
    singbox_availability_changed = Signal(bool)
    install_state_changed = Signal(bool)

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
            parsed = urlparse(raw)
            scheme = (parsed.scheme or "").lower()
            if scheme not in {"udp", "tcp"}:
                raise ValueError("Custom DNS supports only udp:// or tcp:// addresses.")
            host = parsed.hostname
            if not host:
                raise ValueError("Custom DNS address is invalid.")
            port = parsed.port or 53
            return scheme, host, port

        parsed = urlparse(f"//{raw}")
        host = parsed.hostname
        if not host:
            raise ValueError("Custom DNS address is invalid.")
        port = parsed.port or 53
        return "udp", host, port

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

    def _resolve_dns_target(self, host: str, port: int, socktype: int) -> tuple[int, tuple, str]:
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socktype)
        except socket.gaierror as exc:
            raise ValueError(
                f"Cannot resolve Custom DNS host '{host}'. Check internet connection or use an IP address."
            ) from exc
        if not infos:
            raise ValueError(f"Cannot resolve Custom DNS host '{host}'.")

        infos = sorted(infos, key=lambda item: 0 if item[0] == socket.AF_INET else 1)
        family, _socktype, _proto, _canonname, sockaddr = infos[0]
        return family, sockaddr, sockaddr[0]

    def _probe_dns_server(self, scheme: str, family: int, sockaddr: tuple, timeout: float = 2.0) -> None:
        query, query_id = self._dns_query_packet()
        if scheme == "udp":
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, sockaddr)
                response, _ = sock.recvfrom(2048)
            if len(response) < 12 or response[:2] != query_id:
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
        if len(response) < 12 or response[:2] != query_id:
            raise OSError("invalid dns response")

    def _prepare_custom_dns(self, value: str) -> str:
        scheme, host, port = self._parse_custom_dns_target(value)
        socktype = socket.SOCK_DGRAM if scheme == "udp" else socket.SOCK_STREAM
        family, sockaddr, resolved_ip = self._resolve_dns_target(host, port, socktype)
        try:
            self._probe_dns_server(scheme, family, sockaddr)
        except OSError as exc:
            raise ValueError(
                f"Custom DNS server '{host}:{port}' is not responding to DNS queries."
            ) from exc

        try:
            ip_address(resolved_ip)
        except ValueError:
            raise ValueError(f"Resolved Custom DNS address is invalid: {resolved_ip}")

        if ":" in resolved_ip:
            return f"{scheme}://[{resolved_ip}]:{port}"
        return f"{scheme}://{resolved_ip}:{port}"

    def _detect_external_conflict(self) -> str | None:
        try:
            pgrep = subprocess.run(
                ["pgrep", "-x", "sing-box"],
                capture_output=True,
                text=True,
                check=False,
            )
            if pgrep.returncode == 0 and pgrep.stdout.strip():
                return (
                    "Another sing-box process is already running. "
                    "Stop it first (for example: `sudo systemctl stop sing-box`) and try again."
                )
        except OSError:
            pass

        try:
            ip = subprocess.run(
                ["ip", "link", "show", "sb-tun"],
                capture_output=True,
                text=True,
                check=False,
            )
            if ip.returncode == 0:
                return (
                    "Interface sb-tun already exists. Another VPN instance may still be active. "
                    "Disconnect/stop it and try again."
                )
        except OSError:
            pass

        return None

    def has_singbox(self) -> bool:
        return self._resolve_singbox() is not None

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
        if self.process.state() != QProcess.NotRunning:
            self.error.emit("VPN already running")
            return

        conflict = self._detect_external_conflict()
        if conflict:
            self.error.emit(conflict)
            return

        singbox = self._resolve_singbox()
        if not singbox:
            self.error.emit("sing-box not found. Click 'Install sing-box'.")
            self.refresh_singbox_availability()
            return

        if routing and routing.dns_mode == "custom":
            try:
                routing.custom_dns = self._prepare_custom_dns(routing.custom_dns)
            except ValueError as exc:
                self.error.emit(str(exc))
                return
            self.log_line.emit(f"Custom DNS ready: {routing.custom_dns}")

        cfg = build_singbox_config(profile.outbound, routing)
        self._temp_config.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

        self._fatal_reported = False
        self._set_status("connecting")
        self.log_line.emit(f"Starting profile: {profile.name}")
        self.log_line.emit(f"Using sing-box: {singbox}")
        self.process.start(singbox, ["run", "-c", str(self._temp_config)])
        if not self.process.waitForStarted(4000):
            self._set_status("disconnected")
            self.error.emit("failed to start sing-box")
            return

    def disconnect(self) -> None:
        if self.process.state() == QProcess.NotRunning:
            self._set_status("disconnected")
            return

        self._set_status("disconnecting")
        self.process.terminate()
        if not self.process.waitForFinished(3000):
            self.process.kill()
            self.process.waitForFinished(2000)
        self._set_status("disconnected")
        self.log_line.emit("VPN disconnected")

    def _read_stdout(self) -> None:
        output = self._strip_ansi(bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace"))
        for line in output.splitlines():
            self.log_line.emit(line)
            if self._status == "connecting" and "sing-box started" in line.lower():
                self._set_status("connected")

    def _read_stderr(self) -> None:
        output = self._strip_ansi(bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace"))
        for line in output.splitlines():
            self.log_line.emit(line)
            if self._status == "connecting" and "sing-box started" in line.lower():
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
        if self._status != "disconnected":
            self._set_status("disconnected")
            self.log_line.emit("sing-box process exited")

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
        self.refresh_singbox_availability()

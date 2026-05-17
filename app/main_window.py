from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from urllib.parse import unquote

from PySide6.QtCore import QSettings, QTimer, Qt, Signal
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.config_parser import ConfigError, Profile, RoutingOptions, load_profiles, load_profiles_from_text, parse_domains_text
from app.latency import profile_latency_ms
from app.app_paths import ensure_user_owned, import_configs_dir, profiles_path, settings_path
from app.vpn_manager import VpnManager


class MainWindow(QMainWindow):
    latencies_ready = Signal(list)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ambox")
        self.resize(430, 820)
        self.setMinimumSize(360, 680)

        self.profiles: list[Profile] = []
        self.profile_latencies: list[int | None] = []
        self.profile_usage_bytes: list[int] = []
        self._pending_latency_indices: set[int] = set()
        self.connected_index: int | None = None
        self._scan_in_progress = False
        self._latency_has_results = False
        self._last_latency_update_text = "never"
        self._last_auto_switch = 0.0
        self._timeout_streak = 0
        self._usage_store: dict[str, int] = {}
        self._usage_dirty = False
        self._last_usage_persist = 0.0
        self._traffic_last_total: int | None = None

        self.vpn = VpnManager()
        self.settings = QSettings(str(settings_path()), QSettings.IniFormat)
        ensure_user_owned(settings_path())

        self._build_ui()
        self._build_menu()
        self._connect_signals()
        self._restore_settings()
        self._restore_profiles()
        self._set_status("disconnected")
        self.vpn.refresh_singbox_availability()

        self.latency_timer = QTimer(self)
        self.latency_timer.setInterval(10000)
        self.latency_timer.timeout.connect(self.refresh_latencies)
        self.latency_timer.start()

        self.autoswitch_timer = QTimer(self)
        self.autoswitch_timer.setInterval(5000)
        self.autoswitch_timer.timeout.connect(self._maybe_auto_switch)
        self.autoswitch_timer.start()

        self.traffic_timer = QTimer(self)
        self.traffic_timer.setInterval(1000)
        self.traffic_timer.timeout.connect(self._on_traffic_tick)
        self.traffic_timer.start()

    def _build_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("root")
        self.setCentralWidget(root)

        main = QVBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)

        phone_shell = QFrame()
        phone_shell.setObjectName("phoneShell")
        phone_shell.setMaximumWidth(520)
        phone_layout = QVBoxLayout(phone_shell)
        phone_layout.setContentsMargins(10, 10, 10, 10)
        phone_layout.setSpacing(10)

        header = QFrame()
        header.setObjectName("headerCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(12, 10, 12, 10)
        header_layout.setSpacing(6)

        title = QLabel("ambox")
        title.setObjectName("panelTitle")
        header_layout.addWidget(title, 0, Qt.AlignHCenter)

        subtitle = QLabel("Amnezia-like mobile layout")
        subtitle.setObjectName("subtitle")
        header_layout.addWidget(subtitle, 0, Qt.AlignHCenter)

        self.status_badge = QLabel("Disconnected")
        self.status_badge.setAlignment(Qt.AlignCenter)
        self.status_badge.setObjectName("statusDisconnected")
        self.status_badge.setFixedHeight(32)
        header_layout.addWidget(self.status_badge, 0, Qt.AlignHCenter)
        phone_layout.addWidget(header)

        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("contentStack")
        phone_layout.addWidget(self.content_stack, 1)

        connect_tab = QWidget()
        connect_layout = QVBoxLayout(connect_tab)
        connect_layout.setContentsMargins(10, 10, 10, 10)
        connect_layout.setSpacing(10)
        connect_layout.addStretch(1)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setFixedSize(188, 188)
        self.connect_btn.setProperty("vpnState", "disconnected")
        self.connect_btn.clicked.connect(self.toggle_connection)
        connect_layout.addWidget(self.connect_btn, 0, Qt.AlignHCenter)

        self.install_card = QFrame()
        self.install_card.setObjectName("warningCard")
        install_layout = QVBoxLayout(self.install_card)
        install_layout.setContentsMargins(10, 10, 10, 10)
        install_layout.setSpacing(8)

        self.install_notice = QLabel("sing-box is not installed")
        self.install_notice.setObjectName("warn")
        self.install_notice.setWordWrap(True)
        install_layout.addWidget(self.install_notice)

        self.install_btn = QPushButton("Install sing-box")
        self.install_btn.setObjectName("installBtn")
        self.install_btn.clicked.connect(self.install_singbox)
        install_layout.addWidget(self.install_btn)
        self.install_card.setVisible(False)
        connect_layout.addWidget(self.install_card)

        connect_layout.addStretch(1)

        self.quick_profile_frame = QFrame()
        self.quick_profile_frame.setObjectName("quickProfileCard")
        quick_profile_layout = QVBoxLayout(self.quick_profile_frame)
        quick_profile_layout.setContentsMargins(10, 10, 10, 10)
        quick_profile_layout.setSpacing(6)

        quick_profile_label = QLabel("Active profile")
        quick_profile_label.setObjectName("quickProfileTitle")
        quick_profile_layout.addWidget(quick_profile_label)

        self.quick_profile_combo = QComboBox()
        self.quick_profile_combo.setObjectName("quickProfileCombo")
        self.quick_profile_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.quick_profile_combo.setMinimumContentsLength(14)
        quick_profile_layout.addWidget(self.quick_profile_combo)

        quick_profile_hint = QLabel("Switch profile directly from VPN tab.")
        quick_profile_hint.setObjectName("softHint")
        quick_profile_layout.addWidget(quick_profile_hint)

        self.quick_profile_latency_label = QLabel("Latency update: never")
        self.quick_profile_latency_label.setObjectName("softHint")
        quick_profile_layout.addWidget(self.quick_profile_latency_label)

        self.quick_profile_frame.setVisible(False)
        connect_layout.addWidget(self.quick_profile_frame)

        self.content_stack.addWidget(connect_tab)

        profiles_tab = QWidget()
        profiles_layout = QVBoxLayout(profiles_tab)
        profiles_layout.setContentsMargins(10, 10, 10, 10)
        profiles_layout.setSpacing(8)

        profiles_title = QLabel("Profiles")
        profiles_title.setObjectName("sectionTitle")
        profiles_layout.addWidget(profiles_title)

        self.profile_latency_label = QLabel("Latency update: never")
        self.profile_latency_label.setObjectName("softHint")
        profiles_layout.addWidget(self.profile_latency_label)

        self.profile_list = QListWidget()
        self.profile_list.setObjectName("profiles")
        self.profile_list.setContextMenuPolicy(Qt.CustomContextMenu)
        profiles_layout.addWidget(self.profile_list, 1)

        profile_buttons = QHBoxLayout()
        profile_buttons.setSpacing(8)
        import_btn = QPushButton("Import file")
        import_btn.clicked.connect(self.import_config)
        clip_btn = QPushButton("Paste clipboard")
        clip_btn.clicked.connect(self.import_from_clipboard)
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_selected_profile)
        profile_buttons.addWidget(import_btn)
        profile_buttons.addWidget(clip_btn)
        profile_buttons.addWidget(delete_btn)
        profiles_layout.addLayout(profile_buttons)
        self.content_stack.addWidget(profiles_tab)

        settings_tab = QWidget()
        settings_tab_layout = QVBoxLayout(settings_tab)
        settings_tab_layout.setContentsMargins(0, 0, 0, 0)

        settings_scroll = QScrollArea()
        settings_scroll.setObjectName("settingsScroll")
        settings_scroll.setWidgetResizable(True)
        settings_scroll.setFrameShape(QFrame.NoFrame)
        settings_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        settings_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        settings_scroll.setAlignment(Qt.AlignTop)

        settings_body = QWidget()
        settings_layout = QVBoxLayout(settings_body)
        settings_layout.setContentsMargins(10, 10, 10, 10)
        settings_layout.setSpacing(10)
        settings_layout.setAlignment(Qt.AlignTop)

        settings_title = QLabel("Routing and DNS")
        settings_title.setObjectName("sectionTitle")
        settings_layout.addWidget(settings_title)

        perf_card = QFrame()
        perf_card.setObjectName("subCard")
        perf_layout = QVBoxLayout(perf_card)
        perf_layout.setContentsMargins(10, 10, 10, 10)
        perf_layout.setSpacing(8)

        perf_label = QLabel("Performance")
        perf_label.setObjectName("fieldLabel")
        self.auto_switch_checkbox = QCheckBox("Auto switch to lowest latency")
        perf_layout.addWidget(perf_label)
        perf_layout.addWidget(self.auto_switch_checkbox)

        timeout_host = QWidget()
        timeout_row = QHBoxLayout(timeout_host)
        timeout_row.setContentsMargins(0, 0, 0, 0)
        timeout_row.setSpacing(8)
        timeout_desc = QLabel("Probe timeout")
        timeout_desc.setObjectName("softHint")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(200, 5000)
        self.timeout_spin.setValue(1200)
        timeout_unit = QLabel("ms")
        timeout_unit.setObjectName("softHint")
        timeout_row.addWidget(timeout_desc)
        timeout_row.addStretch(1)
        timeout_row.addWidget(self.timeout_spin)
        timeout_row.addWidget(timeout_unit)
        perf_layout.addWidget(timeout_host)
        settings_layout.addWidget(perf_card)

        route_label = QLabel("Routing mode")
        route_label.setObjectName("fieldLabel")
        self.route_mode_combo = QComboBox()
        self.route_mode_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.route_mode_combo.setMinimumContentsLength(16)
        self.route_mode_combo.addItem("Proxy all traffic", "all")
        self.route_mode_combo.addItem("Proxy only listed domains", "only_selected")
        self.route_mode_combo.addItem("Proxy all except listed domains", "all_except_selected")
        settings_layout.addWidget(route_label)
        settings_layout.addWidget(self.route_mode_combo)

        self.routing_mode_hint = QLabel("Domain rules are ignored when 'Proxy all traffic' is selected.")
        self.routing_mode_hint.setWordWrap(True)
        self.routing_mode_hint.setObjectName("softHint")
        settings_layout.addWidget(self.routing_mode_hint)

        self.routing_domains_frame = QFrame()
        self.routing_domains_frame.setObjectName("subCard")
        routing_layout = QVBoxLayout(self.routing_domains_frame)
        routing_layout.setContentsMargins(10, 10, 10, 10)
        routing_layout.setSpacing(8)

        self.include_subdomains_checkbox = QCheckBox("Include subdomains in matches")
        self.include_subdomains_checkbox.setChecked(True)
        routing_layout.addWidget(self.include_subdomains_checkbox)

        self.domains_edit = QPlainTextEdit()
        self.domains_edit.setObjectName("domains")
        self.domains_edit.setPlaceholderText("chatgpt.com\nyoutube.com")
        self.domains_edit.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.domains_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.domains_edit.setMinimumHeight(96)
        self.domains_edit.setMaximumHeight(130)
        routing_layout.addWidget(self.domains_edit)
        settings_layout.addWidget(self.routing_domains_frame)

        dns_label = QLabel("DNS mode")
        dns_label.setObjectName("fieldLabel")
        self.dns_mode_combo = QComboBox()
        self.dns_mode_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.dns_mode_combo.setMinimumContentsLength(16)
        self.dns_mode_combo.addItem("Proxy DNS queries", "proxy")
        self.dns_mode_combo.addItem("Do not proxy DNS (direct)", "direct")
        self.dns_mode_combo.addItem("Custom DNS server", "custom")
        settings_layout.addWidget(dns_label)
        settings_layout.addWidget(self.dns_mode_combo)

        self.custom_dns_frame = QFrame()
        self.custom_dns_frame.setObjectName("subCard")
        custom_dns_layout = QVBoxLayout(self.custom_dns_frame)
        custom_dns_layout.setContentsMargins(10, 10, 10, 10)
        custom_dns_layout.setSpacing(6)

        custom_dns_label = QLabel("Custom DNS")
        custom_dns_label.setObjectName("fieldLabel")
        self.custom_dns_edit = QLineEdit()
        self.custom_dns_edit.setObjectName("customDns")
        self.custom_dns_edit.setPlaceholderText("1.1.1.1 or dns.google")
        custom_dns_layout.addWidget(custom_dns_label)
        custom_dns_layout.addWidget(self.custom_dns_edit)

        self.custom_dns_hint = QLabel("Used only when 'Custom DNS server' is selected.")
        self.custom_dns_hint.setObjectName("softHint")
        custom_dns_layout.addWidget(self.custom_dns_hint)
        settings_layout.addWidget(self.custom_dns_frame)

        hint = QLabel("Settings moved here to keep a phone-like bottom navigation layout.")
        hint.setWordWrap(True)
        hint.setObjectName("hint")
        settings_layout.addWidget(hint)
        settings_layout.addStretch(1)

        settings_scroll.setWidget(settings_body)
        settings_tab_layout.addWidget(settings_scroll)
        self.content_stack.addWidget(settings_tab)

        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.setContentsMargins(10, 10, 10, 10)
        logs_layout.setSpacing(8)

        logs_title = QLabel("Connection logs")
        logs_title.setObjectName("sectionTitle")
        logs_layout.addWidget(logs_title)

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setObjectName("logs")
        logs_layout.addWidget(self.logs, 1)
        self.content_stack.addWidget(logs_tab)

        bottom_nav = QFrame()
        bottom_nav.setObjectName("bottomNav")
        nav_layout = QHBoxLayout(bottom_nav)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(8)

        self.nav_buttons: list[QPushButton] = []
        for index, label in enumerate(["VPN", "Profiles", "Settings", "Logs"]):
            btn = QPushButton(label)
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _checked=False, i=index: self._set_bottom_page(i))
            nav_layout.addWidget(btn, 1)
            self.nav_buttons.append(btn)

        phone_layout.addWidget(bottom_nav)
        self._set_bottom_page(0)

        main.addWidget(phone_shell, 1, Qt.AlignHCenter)

        self.setStyleSheet(
            """
            QWidget {
              color: #d9dce3;
              font-family: "Noto Sans", "Segoe UI", sans-serif;
              font-size: 13px;
            }
            QWidget#root {
              background: qradialgradient(cx:0.5, cy:0.04, radius:1.2,
                fx:0.5, fy:0.04, stop:0 #1b1e28, stop:0.42 #11141d, stop:1 #090b11);
            }
            QFrame#phoneShell {
              background-color: #0f1119;
              border: none;
              border-radius: 0px;
            }
            QFrame#headerCard {
              background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #171b26, stop:1 #131722);
              border: 1px solid #2d3340;
              border-radius: 12px;
            }
            QFrame#warningCard {
              background-color: #2d241f;
              border: 1px solid #664f41;
              border-radius: 12px;
            }
            #panelTitle {
              font-size: 16px;
              font-weight: 700;
              color: #f0f1f5;
            }
            #subtitle, #softHint, #hint {
              color: #8f95a3;
            }
            #sectionTitle {
              font-size: 14px;
              font-weight: 700;
              color: #eceef2;
            }
            #fieldLabel {
              color: #cbcfd8;
              font-weight: 600;
              margin-bottom: 2px;
            }
            #quickProfileTitle {
              color: #f0c998;
              font-weight: 700;
              font-size: 13px;
            }
            QPushButton {
              background-color: #1c202b;
              border: 1px solid #3a3f4d;
              border-radius: 10px;
              padding: 8px 11px;
              font-weight: 600;
            }
            QPushButton:hover {
              background-color: #252a36;
              border: 1px solid #4a5161;
            }
            QPushButton:pressed {
              background-color: #181c26;
            }
            #connectBtn {
              background: qradialgradient(cx:0.5, cy:0.5, radius:0.8,
                fx:0.5, fy:0.5, stop:0 #121620, stop:1 #0c1018);
              border: 2px solid #f0f2f6;
              border-radius: 94px;
              font-size: 30px;
              font-weight: 700;
              color: #f4f6fa;
              padding: 0;
            }
            #connectBtn:hover {
              border: 2px solid #f3b66a;
              color: #f3b66a;
            }
            #connectBtn[vpnState="connected"] {
              border: 2px solid #f3b66a;
              color: #f3b66a;
            }
            #connectBtn[vpnState="connected"]:hover {
              border: 2px solid #ffcc8e;
              color: #ffcc8e;
            }
            #installBtn {
              background-color: #3a2a23;
              border: 1px solid #6a4f43;
              color: #ffe3c9;
            }
            #installBtn:hover {
              background-color: #4a3329;
            }
            #warn {
              color: #ffcfad;
              font-weight: 700;
            }
            QCheckBox {
              color: #d9dce3;
            }
            QCheckBox::indicator {
              width: 18px;
              height: 18px;
            }
            QCheckBox::indicator:unchecked {
              border: 1px solid #535a68;
              background: #10151f;
              border-radius: 4px;
            }
            QCheckBox::indicator:checked {
              border: 1px solid #e0a85f;
              background: #d78f3a;
              border-radius: 4px;
            }
            QComboBox, QLineEdit, QSpinBox, #domains {
              border: 1px solid #3d4453;
              border-radius: 8px;
              padding: 6px 8px;
              background: #0f141f;
              color: #e0e4ec;
            }
            QComboBox QAbstractItemView {
              background: #131825;
              border: 1px solid #323a49;
              selection-background-color: #3a3027;
            }
            QWidget:disabled {
              color: #757d8c;
            }
            QFrame#subCard {
              background-color: #111621;
              border: 1px solid #2c3341;
              border-radius: 10px;
            }
            QFrame#quickProfileCard {
              background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #171420, stop:1 #131822);
              border: 1px solid #5c4735;
              border-radius: 10px;
            }
            QComboBox#quickProfileCombo {
              border: 1px solid #7c5a3f;
              background: #15111a;
              color: #f4d4a8;
              font-weight: 700;
              min-height: 36px;
              padding-right: 24px;
            }
            QComboBox#quickProfileCombo:hover {
              border: 1px solid #a7774c;
              color: #ffd9a5;
            }
            #profiles {
              border: 1px solid #333948;
              border-radius: 11px;
              background-color: #101520;
              outline: none;
            }
            #profiles::item {
              padding: 9px;
              border-bottom: 1px solid #232938;
            }
            #profiles::item:selected {
              background: #2f2720;
              border: 1px solid #a7763f;
              border-radius: 8px;
              color: #f0b774;
            }
            #logs {
              background-color: #0d111a;
              border: 1px solid #323a49;
              border-radius: 10px;
              font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
              color: #d6dbe4;
            }
            QFrame#bottomNav {
              background: transparent;
              border: none;
            }
            QPushButton#navBtn {
              border: 1px solid #2f3645;
              border-radius: 10px;
              background: #131823;
              color: #9ca3b2;
              min-height: 44px;
              font-size: 13px;
              font-weight: 600;
              padding: 6px 8px;
            }
            QPushButton#navBtn:hover {
              background: #171d2a;
              border: 1px solid #445065;
              color: #c9d2e0;
            }
            QPushButton#navBtn:checked {
              background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                stop:0 #3b2f22, stop:1 #2f241a);
              border: 1px solid #b9834b;
              color: #f0b774;
            }
            QScrollArea#settingsScroll {
              border: none;
              background: transparent;
            }
            QLabel#statusDisconnected, QLabel#statusConnecting,
            QLabel#statusConnected, QLabel#statusDisconnecting {
              border-radius: 10px;
              font-weight: 700;
              font-size: 13px;
              padding: 5px 12px;
            }
            QLabel#statusDisconnected { background-color: #2a2f3b; color: #b6bfce; }
            QLabel#statusConnecting { background-color: #3a3025; color: #ffcc9a; }
            QLabel#statusConnected { background-color: #2d3529; color: #a9e09a; }
            QLabel#statusDisconnecting { background-color: #3a3238; color: #e0c7d3; }
            """
        )

    def _set_bottom_page(self, index: int) -> None:
        if index < 0 or index >= self.content_stack.count():
            return
        self.content_stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)

    def _profile_item_text(self, index: int) -> str:
        profile = self.profiles[index]
        latency = self.profile_latencies[index] if index < len(self.profile_latencies) else None
        if index in self._pending_latency_indices or not self._latency_has_results:
            suffix = "checking..."
        else:
            suffix = "timeout" if latency is None else f"{latency} ms"
        usage = self.profile_usage_bytes[index] if index < len(self.profile_usage_bytes) else 0
        return f"{profile.name}  [{suffix} | {self._format_bytes(usage)}]"

    def _profile_usage_key(self, profile: Profile) -> str:
        try:
            return json.dumps(profile.outbound, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError):
            return profile.name

    def _format_bytes(self, value: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(max(0, value))
        unit = units[0]
        for unit in units:
            if size < 1024 or unit == units[-1]:
                break
            size /= 1024
        if unit == "B":
            return f"{int(size)} {unit}"
        return f"{size:.1f} {unit}"

    def _read_interface_counters(self, interface: str = "sb-tun") -> tuple[int, int] | None:
        base = Path("/sys/class/net") / interface / "statistics"
        try:
            rx_text = (base / "rx_bytes").read_text(encoding="utf-8").strip()
            tx_text = (base / "tx_bytes").read_text(encoding="utf-8").strip()
            return int(rx_text), int(tx_text)
        except (OSError, ValueError):
            return None

    def _persist_usage_store(self, force: bool = False) -> None:
        if not self._usage_dirty and not force:
            return
        now = time.monotonic()
        if not force and (now - self._last_usage_persist) < 5.0:
            return
        self.settings.setValue("profile_usage_bytes", json.dumps(self._usage_store, ensure_ascii=True))
        self.settings.sync()
        ensure_user_owned(settings_path())
        self._usage_dirty = False
        self._last_usage_persist = now

    def _on_traffic_tick(self) -> None:
        if self.vpn.status != "connected":
            self._traffic_last_total = None
            return
        if self.connected_index is None or self.connected_index >= len(self.profiles):
            self._traffic_last_total = None
            return

        counters = self._read_interface_counters()
        if counters is None:
            return
        total = counters[0] + counters[1]
        if self._traffic_last_total is None:
            self._traffic_last_total = total
            return

        delta = total - self._traffic_last_total
        self._traffic_last_total = total
        if delta <= 0:
            return

        idx = self.connected_index
        self.profile_usage_bytes[idx] += delta
        key = self._profile_usage_key(self.profiles[idx])
        self._usage_store[key] = self.profile_usage_bytes[idx]
        self._usage_dirty = True

        item = self.profile_list.item(idx)
        if item is not None:
            item.setText(self._profile_item_text(idx))
        if idx < self.quick_profile_combo.count():
            self.quick_profile_combo.setItemText(idx, self._profile_item_text(idx))
        self._persist_usage_store()

    def _refresh_latency_update_labels(self) -> None:
        text = f"Latency update: {self._last_latency_update_text}"
        self.profile_latency_label.setText(text)
        self.quick_profile_latency_label.setText(text)

    def _sync_quick_profile_selector(self) -> None:
        labels = [self._profile_item_text(idx) for idx in range(len(self.profiles))]

        current = self._selected_profile_index()
        if current is None and labels:
            current = 0

        self.quick_profile_combo.blockSignals(True)
        if self.quick_profile_combo.count() != len(labels):
            self.quick_profile_combo.clear()
            for label in labels:
                self.quick_profile_combo.addItem(label)
        else:
            for idx, label in enumerate(labels):
                if self.quick_profile_combo.itemText(idx) != label:
                    self.quick_profile_combo.setItemText(idx, label)
        if current is not None and 0 <= current < self.quick_profile_combo.count():
            self.quick_profile_combo.setCurrentIndex(current)
        self.quick_profile_combo.blockSignals(False)

        self.quick_profile_frame.setVisible(len(labels) > 1)
        self.quick_profile_combo.setEnabled(len(labels) > 1)

    def _on_profile_list_row_changed(self, row: int) -> None:
        if row < 0:
            return
        if row >= self.quick_profile_combo.count():
            return
        if self.quick_profile_combo.currentIndex() == row:
            return
        self.quick_profile_combo.blockSignals(True)
        self.quick_profile_combo.setCurrentIndex(row)
        self.quick_profile_combo.blockSignals(False)

    def _on_quick_profile_changed(self, index: int) -> None:
        if index < 0 or index >= len(self.profiles):
            return
        if self.profile_list.currentRow() == index:
            return
        self.profile_list.setCurrentRow(index)

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("File")

        import_action = QAction("Import from file", self)
        import_action.triggered.connect(self.import_config)
        menu.addAction(import_action)

        import_clip_action = QAction("Import from clipboard", self)
        import_clip_action.setShortcuts([QKeySequence("Ctrl+V"), QKeySequence("Ctrl+Shift+V")])
        import_clip_action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        import_clip_action.triggered.connect(self.import_from_clipboard)
        menu.addAction(import_clip_action)

        install_action = QAction("Install sing-box", self)
        install_action.triggered.connect(self.install_singbox)
        menu.addAction(install_action)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)

    def _connect_signals(self) -> None:
        self.vpn.status_changed.connect(self._on_vpn_status_changed)
        self.vpn.log_line.connect(self._append_log)
        self.vpn.error.connect(self._show_error)
        self.vpn.singbox_availability_changed.connect(self._on_singbox_availability_changed)
        self.vpn.install_state_changed.connect(self._on_install_state_changed)
        self.latencies_ready.connect(self._on_latencies_ready)
        self.profile_list.currentRowChanged.connect(self._on_profile_list_row_changed)
        self.profile_list.customContextMenuRequested.connect(self._show_profile_context_menu)
        self.quick_profile_combo.currentIndexChanged.connect(self._on_quick_profile_changed)
        self.auto_switch_checkbox.toggled.connect(lambda checked: self.settings.setValue("auto_switch", checked))
        self.timeout_spin.valueChanged.connect(lambda value: self.settings.setValue("timeout_ms", value))
        self.route_mode_combo.currentIndexChanged.connect(self._on_route_mode_changed)
        self.dns_mode_combo.currentIndexChanged.connect(self._on_dns_mode_changed)
        self.custom_dns_edit.textChanged.connect(
            lambda value: self.settings.setValue("route_custom_dns", value)
        )
        self.include_subdomains_checkbox.toggled.connect(
            lambda checked: self.settings.setValue("route_include_subdomains", checked)
        )
        self.domains_edit.textChanged.connect(
            lambda: self.settings.setValue("route_domains_text", self.domains_edit.toPlainText())
        )

    def _restore_settings(self) -> None:
        auto_switch = self.settings.value("auto_switch", False, type=bool)
        timeout_ms = self.settings.value("timeout_ms", 1200, type=int)
        route_mode = self.settings.value("route_mode", "all", type=str) or "all"
        route_dns_mode = self.settings.value("route_dns_mode", "", type=str) or ""
        if not route_dns_mode:
            legacy_proxy_dns = self.settings.value("route_proxy_dns", True, type=bool)
            route_dns_mode = "proxy" if legacy_proxy_dns else "direct"
        route_custom_dns = self.settings.value("route_custom_dns", "", type=str) or ""
        include_subdomains = self.settings.value("route_include_subdomains", True, type=bool)
        route_domains_text = self.settings.value("route_domains_text", "", type=str) or ""
        usage_raw = self.settings.value("profile_usage_bytes", "{}", type=str) or "{}"
        try:
            parsed_usage = json.loads(usage_raw)
            if isinstance(parsed_usage, dict):
                self._usage_store = {str(k): int(v) for k, v in parsed_usage.items()}
            else:
                self._usage_store = {}
        except (ValueError, TypeError):
            self._usage_store = {}

        self.auto_switch_checkbox.setChecked(auto_switch)
        self.timeout_spin.setValue(timeout_ms)
        route_index = self.route_mode_combo.findData(route_mode)
        if route_index < 0:
            route_index = 0
        self.route_mode_combo.setCurrentIndex(route_index)
        dns_mode_index = self.dns_mode_combo.findData(route_dns_mode)
        if dns_mode_index < 0:
            dns_mode_index = 0
        self.dns_mode_combo.setCurrentIndex(dns_mode_index)
        self.custom_dns_edit.setText(route_custom_dns)
        self.include_subdomains_checkbox.setChecked(include_subdomains)
        self.domains_edit.setPlainText(route_domains_text)
        self._update_routing_controls()
        self._update_dns_controls()

    def _restore_profiles(self) -> None:
        path = profiles_path()
        if not path.exists():
            return

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._append_log(f"Failed to load saved profiles: {exc}")
            return

        raw_profiles = data.get("profiles") if isinstance(data, dict) else None
        if not isinstance(raw_profiles, list):
            self._append_log("Saved profiles file has invalid format")
            return

        loaded: list[Profile] = []
        for idx, item in enumerate(raw_profiles, start=1):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            outbound = item.get("outbound")
            if not isinstance(name, str) or not isinstance(outbound, dict):
                continue
            loaded.append(Profile(name=name or f"Profile {idx}", outbound=outbound))

        if loaded:
            self._apply_loaded_profiles(loaded, persist=False)
            self._append_log(f"Loaded {len(loaded)} saved profile(s) from {path}")

    def _save_profiles(self) -> None:
        payload = {
            "profiles": [
                {"name": profile.name, "outbound": profile.outbound}
                for profile in self.profiles
            ]
        }
        try:
            path = profiles_path()
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            ensure_user_owned(path)
        except OSError as exc:
            self._append_log(f"Failed to save profiles: {exc}")

    def _on_route_mode_changed(self, _index: int = -1) -> None:
        self.settings.setValue("route_mode", self.route_mode_combo.currentData())
        self._update_routing_controls()

    def _on_dns_mode_changed(self, _index: int = -1) -> None:
        self.settings.setValue("route_dns_mode", self.dns_mode_combo.currentData())
        self._update_dns_controls()

    def _update_routing_controls(self) -> None:
        needs_domains = self.route_mode_combo.currentData() in {"only_selected", "all_except_selected"}
        self.routing_domains_frame.setVisible(needs_domains)
        self.routing_mode_hint.setVisible(needs_domains)
        if needs_domains:
            self.routing_mode_hint.setText("Routing uses the domain list below in this mode.")
        else:
            self.routing_mode_hint.setText("")

    def _update_dns_controls(self) -> None:
        needs_custom_dns = self.dns_mode_combo.currentData() == "custom"
        self.custom_dns_frame.setVisible(needs_custom_dns)
        if needs_custom_dns:
            self.custom_dns_hint.setText("Enter DNS server as IP/host, optional scheme (udp:// or tcp://).")
        else:
            self.custom_dns_hint.setText("Custom DNS is disabled in this mode.")

    def _on_singbox_availability_changed(self, available: bool) -> None:
        self.install_card.setVisible(not available)
        self.install_notice.setVisible(not available)
        self.install_btn.setVisible(not available)
        self.connect_btn.setEnabled(available)

    def _on_install_state_changed(self, running: bool) -> None:
        self.install_btn.setEnabled(not running)
        if running:
            self.install_btn.setText("Installing...")
        else:
            self.install_btn.setText("Install sing-box")

    def install_singbox(self) -> None:
        self.vpn.install_singbox()

    def import_config(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open config",
            str(import_configs_dir()),
            "Config files (*.json *.txt *.conf);;All files (*)",
        )
        if not path_str:
            return

        try:
            loaded = load_profiles(Path(path_str))
        except (OSError, ValueError, ConfigError) as exc:
            self._show_error(f"Failed to import config: {exc}")
            return

        self._apply_loaded_profiles(loaded)
        self._append_log(f"Imported {len(loaded)} profile(s) from file: {path_str}")

    def import_from_clipboard(self) -> None:
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip()
        if not text:
            self._show_error("Clipboard is empty")
            return

        maybe_path = text
        if text.startswith("file://"):
            maybe_path = unquote(text.removeprefix("file://"))

        path_candidate = Path(maybe_path).expanduser()
        if "\n" not in maybe_path and path_candidate.is_file():
            try:
                loaded = load_profiles(path_candidate)
            except (OSError, ValueError, ConfigError) as exc:
                self._show_error(
                    "Clipboard contains a file path, but this file is not a valid text VPN config. "
                    "Copy a vless/vmess/trojan/ss link or a JSON config."
                )
                return
            self._apply_loaded_profiles(loaded)
            self._append_log(f"Imported {len(loaded)} profile(s) from clipboard path: {path_candidate}")
            return

        try:
            loaded = load_profiles_from_text(text)
        except (ValueError, ConfigError) as exc:
            self._show_error(f"Failed to import from clipboard: {exc}")
            return

        self._apply_loaded_profiles(loaded)
        self._append_log(f"Imported {len(loaded)} profile(s) from clipboard")

    def delete_selected_profile(self) -> None:
        index = self._selected_profile_index()
        if index is None:
            self._show_error("Choose a profile to delete")
            return

        profile = self.profiles[index]
        if self.connected_index == index:
            self.vpn.disconnect()

        del self.profiles[index]
        del self.profile_latencies[index]
        del self.profile_usage_bytes[index]
        self._pending_latency_indices = {
            item - 1 if item > index else item
            for item in self._pending_latency_indices
            if item != index
        }

        if self.connected_index is not None and self.connected_index > index:
            self.connected_index -= 1

        self.profile_list.takeItem(index)
        self._usage_store.pop(self._profile_usage_key(profile), None)
        self._usage_dirty = True
        self._persist_usage_store(force=True)
        self._save_profiles()

        if self.profiles:
            self.profile_list.setCurrentRow(min(index, len(self.profiles) - 1))
        else:
            self.profile_list.clearSelection()
            self._latency_has_results = False
            self._last_latency_update_text = "never"
        self._sync_quick_profile_selector()
        self._refresh_latency_update_labels()
        self._append_log(f"Deleted profile: {profile.name}")

    def _show_profile_context_menu(self, pos) -> None:
        item = self.profile_list.itemAt(pos)
        if item is None:
            return

        row = self.profile_list.row(item)
        if row < 0 or row >= len(self.profiles):
            return

        if self.profile_list.currentRow() != row:
            self.profile_list.setCurrentRow(row)

        menu = QMenu(self)
        delete_action = menu.addAction("Delete")
        selected_action = menu.exec(self.profile_list.viewport().mapToGlobal(pos))
        if selected_action is delete_action:
            self.delete_selected_profile()

    def _apply_loaded_profiles(self, loaded: list[Profile], persist: bool = True) -> None:
        if not loaded:
            return

        start_index = len(self.profiles)
        for profile in loaded:
            idx = len(self.profiles)
            self.profiles.append(profile)
            self.profile_latencies.append(None)
            usage = int(self._usage_store.get(self._profile_usage_key(profile), 0))
            self.profile_usage_bytes.append(usage)
            self._pending_latency_indices.add(idx)
            QListWidgetItem(self._profile_item_text(idx), self.profile_list)
        if not self._latency_has_results:
            self._last_latency_update_text = "pending..."
        self.profile_list.setCurrentRow(start_index if start_index < len(self.profiles) else 0)
        self._sync_quick_profile_selector()
        self._refresh_latency_update_labels()
        if persist:
            self._save_profiles()
        self.refresh_latencies()

    def _selected_profile_index(self) -> int | None:
        row = self.profile_list.currentRow()
        if row < 0 or row >= len(self.profiles):
            return None
        return row

    def toggle_connection(self) -> None:
        if self.vpn.status in {"connected", "connecting"}:
            self.vpn.disconnect()
            return

        index = self._selected_profile_index()
        if self.auto_switch_checkbox.isChecked():
            best = self._best_profile_index()
            if best is not None:
                index = best
                self.profile_list.setCurrentRow(best)

        if index is None:
            self._show_error("Choose a profile first")
            return

        self._connect_profile(index)

    def _connect_profile(self, index: int) -> None:
        if index < 0 or index >= len(self.profiles):
            return

        routing = self._routing_options()
        if routing.mode == "only_selected" and not routing.domains:
            self._show_error("Add at least one domain for 'Proxy only listed domains' mode.")
            return
        if routing.dns_mode == "custom" and not routing.custom_dns.strip():
            self._show_error("Enter a Custom DNS server address.")
            return

        if self.vpn.status in {"connected", "connecting"}:
            self.vpn.disconnect()

        self.connected_index = index
        profile = self.profiles[index]
        self.vpn.connect_profile(profile, routing)
        if self.vpn.status == "disconnected":
            self.connected_index = None

    def _routing_options(self) -> RoutingOptions:
        mode = str(self.route_mode_combo.currentData() or "all")
        domains = parse_domains_text(self.domains_edit.toPlainText())
        return RoutingOptions(
            mode=mode,
            dns_mode=str(self.dns_mode_combo.currentData() or "proxy"),
            custom_dns=self.custom_dns_edit.text().strip(),
            include_subdomains=self.include_subdomains_checkbox.isChecked(),
            domains=domains,
        )

    def refresh_latencies(self) -> None:
        if not self.profiles or self._scan_in_progress:
            return

        timeout_sec = self.timeout_spin.value() / 1000.0
        snapshot = list(self.profiles)
        self._scan_in_progress = True
        worker = threading.Thread(
            target=self._scan_latency_worker,
            args=(snapshot, timeout_sec),
            daemon=True,
        )
        worker.start()

    def _scan_latency_worker(self, profiles: list[Profile], timeout_sec: float) -> None:
        results = [profile_latency_ms(profile, timeout_sec) for profile in profiles]
        self.latencies_ready.emit(results)

    def _on_latencies_ready(self, latencies: list[int | None]) -> None:
        self._scan_in_progress = False
        if len(latencies) != len(self.profiles):
            return

        self.profile_latencies = latencies
        self._pending_latency_indices.clear()
        self._latency_has_results = True
        self._last_latency_update_text = time.strftime("%H:%M:%S")
        for idx in range(len(self.profiles)):
            item = self.profile_list.item(idx)
            if item is not None:
                item.setText(self._profile_item_text(idx))
        self._sync_quick_profile_selector()
        self._refresh_latency_update_labels()

    def _best_profile_index(self) -> int | None:
        best_index: int | None = None
        best_latency: int | None = None

        for idx, latency in enumerate(self.profile_latencies):
            if latency is None:
                continue
            if best_latency is None or latency < best_latency:
                best_latency = latency
                best_index = idx

        return best_index

    def _maybe_auto_switch(self) -> None:
        if not self.auto_switch_checkbox.isChecked():
            return
        if self.vpn.status != "connected":
            return
        if self.connected_index is None:
            return
        if self.connected_index >= len(self.profiles):
            return

        self.refresh_latencies()
        if not self.profile_latencies:
            return

        current = self.connected_index
        current_latency = self.profile_latencies[current] if current < len(self.profile_latencies) else None
        best = self._best_profile_index()
        if best is None or best == current:
            if current_latency is not None and current_latency <= self.timeout_spin.value():
                self._timeout_streak = 0
            return

        if current_latency is None or current_latency > self.timeout_spin.value():
            self._timeout_streak += 1
        else:
            self._timeout_streak = 0

        best_latency = self.profile_latencies[best]
        if best_latency is None:
            return

        should_switch = False
        if current_latency is None and self._timeout_streak >= 2:
            should_switch = True
        elif current_latency is not None:
            if current_latency > self.timeout_spin.value():
                should_switch = True
            elif best_latency + 120 < current_latency:
                should_switch = True

        cooldown_ok = (time.monotonic() - self._last_auto_switch) >= 20.0
        if should_switch and cooldown_ok:
            self._last_auto_switch = time.monotonic()
            self._append_log(
                f"Auto switch: {self.profiles[current].name} -> {self.profiles[best].name} "
                f"({current_latency if current_latency is not None else 'timeout'} -> {best_latency} ms)"
            )
            self.profile_list.setCurrentRow(best)
            self._connect_profile(best)

    def _on_vpn_status_changed(self, status: str) -> None:
        self._set_status(status)
        if status == "disconnected":
            self.connected_index = None
            self._timeout_streak = 0
            self._traffic_last_total = None
            self._persist_usage_store(force=True)

    def _set_status(self, status: str) -> None:
        mapping = {
            "disconnected": ("Disconnected", "statusDisconnected", "Connect"),
            "connecting": ("Connecting...", "statusConnecting", "Stop"),
            "connected": ("Connected", "statusConnected", "Stop"),
            "disconnecting": ("Disconnecting...", "statusDisconnecting", "Stop"),
        }
        text, class_name, button_text = mapping.get(status, (status, "statusDisconnected", "Connect"))
        self.status_badge.setText(text)
        self.status_badge.setObjectName(class_name)
        self.status_badge.style().unpolish(self.status_badge)
        self.status_badge.style().polish(self.status_badge)
        self.connect_btn.setText(button_text)
        self.connect_btn.setProperty("vpnState", "connected" if status == "connected" else "disconnected")
        self.connect_btn.style().unpolish(self.connect_btn)
        self.connect_btn.style().polish(self.connect_btn)

    def _append_log(self, text: str) -> None:
        self.logs.append(text)

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Error", message)
        self._append_log(f"ERROR: {message}")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._persist_usage_store(force=True)
        self.settings.sync()
        ensure_user_owned(settings_path())
        self.vpn.disconnect()
        super().closeEvent(event)

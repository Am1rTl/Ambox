from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from PySide6.QtCore import QEvent, QFileInfo, QSize, QSettings, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QIcon, QKeySequence, QPainter, QPen, QPixmap, QShortcut
from PySide6.QtNetwork import QLocalServer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFileIconProvider,
    QFrame,
    QHBoxLayout,
    QInputDialog,
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
    QSizePolicy,
    QStyle,
    QSpinBox,
    QStackedWidget,
    QSystemTrayIcon,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.app_paths import ensure_user_owned, import_configs_dir, log_path, profiles_path, settings_path
from app.desktop_apps import DesktopApp, identity, installed_applications, merge_applications, running_applications
from app.theme import STYLESHEET
from app.security import atomic_private_json, redact, redacted_structure
from app.quality import QualityTracker, should_switch
from app.profile_sources import profile_indices_for_source
from app.diagnostics import connected_diagnostics
from app.route_presets import PRESETS, preset_values
from app.dashboard import TrafficChart
from app.config_parser import (
    ConfigError,
    Profile,
    RoutingOptions,
    load_happ_link,
    load_profiles,
    load_profiles_from_text,
    parse_route_targets,
)
from app.happ_links import is_happ_link
from app.latency import MAX_PROBE_WORKERS, profile_latency_ms, probe_active_connection
from app.xray_bundle import ensure_rule_sets, required_rule_sets
from app.locations import detect_location, iso_to_flag
from app.subscriptions import (
    Subscription,
    SubscriptionStore,
    derive_subscription_name,
    fetch_subscription_profiles,
    format_bytes,
    generate_subscription_id,
    is_likely_subscription_url,
    subscription_due,
)
from app.subscriptions_dialog import AddSubscriptionDialog, SubscriptionsPanel
from app.net_session import IFACE_NAME
from app.single_instance import LINK_PREFIX, SERVER_NAME
from app.vpn_manager import VpnManager


class ProfileListWidget(QListWidget):
    files_dropped = Signal(list)
    links_dropped = Signal(list)
    items_reordered = Signal(int, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._drag_row: int | None = None
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDropIndicatorShown(True)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

    def startDrag(self, supported_actions) -> None:  # type: ignore[override]
        self._drag_row = self.currentRow()
        super().startDrag(supported_actions)

    def dragEnterEvent(self, event) -> None:  # type: ignore[override]
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:  # type: ignore[override]
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:  # type: ignore[override]
        if event.mimeData().hasUrls():
            paths = []
            links = []
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    local_path = url.toLocalFile()
                    if local_path:
                        paths.append(local_path)
                elif url.scheme().lower() in {"happ", "http", "https"}:
                    link = url.toString()
                    if link:
                        links.append(link)
            if paths:
                self.files_dropped.emit(paths)
            if links:
                self.links_dropped.emit(links)
            if paths or links:
                event.acceptProposedAction()
                return

        old_row = self._drag_row
        super().dropEvent(event)
        new_row = self.currentRow()
        if old_row is None or new_row < 0 or old_row == new_row:
            return
        self.items_reordered.emit(old_row, new_row)


class MainWindow(QMainWindow):
    latencies_ready = Signal(int, list)
    happ_import_finished = Signal(str, object, str)
    subscription_update_finished = Signal(str, object, object, str)
    # Worker threads must not touch widgets; they log through this queued signal.
    worker_log = Signal(str)
    resume_probe_finished = Signal(bool)
    diagnostics_ready = Signal(object)

    def __init__(self, initial_link: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("ambox")
        self.resize(540, 720)
        self.setMinimumSize(400, 565)
        self._app_icon = self._build_app_icon()
        self.setWindowIcon(self._app_icon)

        self.profiles: list[Profile] = []
        self.profile_latencies: list[int | None] = []
        self.profile_usage_bytes: list[int] = []
        self._pending_latency_indices: set[int] = set()
        self._visible_profile_indices: list[int] = []
        self._profile_row_items: dict[int, QListWidgetItem] = {}
        self.connected_index: int | None = None
        self._scan_in_progress = False
        self._pending_latency_refresh = False
        self._active_scan_id = 0
        self._active_scan_profile_ids: list[str] = []
        self._latency_has_results = False
        self._last_latency_update_text = "never"
        self._last_auto_switch = 0.0
        self._timeout_streak = 0
        self._usage_store: dict[str, int] = {}
        self._usage_dirty = False
        self._last_usage_persist = 0.0
        self._traffic_last_total: int | None = None
        self._last_used_store: dict[str, float] = {}
        self._live_apply_timer = QTimer(self)
        self._live_apply_timer.setSingleShot(True)
        self._live_apply_timer.setInterval(650)
        self._live_apply_timer.timeout.connect(self._apply_routing_changes_live)
        self._last_vpn_status = "disconnected"
        self.quality = QualityTracker()
        self.favorite_profile_ids: set[str] = set()
        self._last_quality_persist = 0.0
        self._last_switch_scan = -1
        self._switch_candidate: str | None = None
        self._switch_candidate_votes = 0
        self._last_traffic_counters: tuple[int, int] | None = None
        self._last_traffic_sample = time.monotonic()
        self._desired_profile_id: str | None = None
        self._reconnect_attempts = 0
        self._reconnect_timer = QTimer(self)
        self._reconnect_timer.setSingleShot(True)
        self._reconnect_timer.timeout.connect(self._attempt_reconnect)
        self._subs_inflight: set[str] = set()
        self._subs_silent: set[str] = set()
        self._pending_subscription_links: dict[str, str] = {}
        self._subscription_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='ambox-sub')
        self._subscription_retry_at: dict[str, float] = {}
        self._subscription_failures: dict[str, int] = {}
        self._last_quota_notice: dict[str, float] = {}
        self._diag_running = False
        self._installed_apps: list[DesktopApp] | None = None
        self._desktop_icons: dict[str, QIcon] = {}

        self.subscription_store = SubscriptionStore()
        self._selected_location = "ALL"
        self._profile_source = "manual"
        self._selected_sub_id = ""

        self.vpn = VpnManager()
        self.settings = QSettings(str(settings_path()), QSettings.IniFormat)
        self._protect_settings_file()

        self._build_ui()
        self._build_menu()
        self._connect_signals()
        self._restore_settings()
        self._restore_profiles()
        self._setup_notifications()
        self._sleep_was_connected = False
        self._sleep_connected_index: int | None = None
        self._instance_server: QLocalServer | None = None
        self._setup_instance_server()
        self._setup_sleep_monitor()
        self._set_status("disconnected")
        self.vpn.refresh_singbox_availability()
        # Deferred: a modal dialog must not block window construction at startup.
        QTimer.singleShot(0, self._warn_if_not_running_as_sudo)
        startup_warning = self.vpn.take_startup_warning()
        if startup_warning:
            self._append_log(f'WARNING: {startup_warning}')
            logging.warning(startup_warning)
        for env_warning in self.vpn.environment_warnings():
            self._append_log(f'WARNING: {env_warning}')
            logging.warning(env_warning)

        self.latency_timer = QTimer(self)
        self.latency_timer.setInterval(60000)
        self.latency_timer.timeout.connect(self.refresh_latencies)
        self.latency_timer.start()

        self.autoswitch_timer = QTimer(self)
        self.autoswitch_timer.setInterval(20000)
        self.autoswitch_timer.timeout.connect(self._maybe_auto_switch)
        self.autoswitch_timer.start()

        self.traffic_timer = QTimer(self)
        self.traffic_timer.setInterval(1000)
        self.traffic_timer.timeout.connect(self._on_traffic_tick)
        self.traffic_timer.start()

        self.subscription_timer = QTimer(self)
        self.subscription_timer.setInterval(30 * 60 * 1000)
        self.subscription_timer.timeout.connect(self._auto_update_subscriptions_startup)
        self.subscription_timer.start()

        if self.settings.value("auto_update_subs", True, type=bool):
            QTimer.singleShot(1500, self._auto_update_subscriptions_startup)

        if initial_link and (is_happ_link(initial_link) or is_likely_subscription_url(initial_link)):
            QTimer.singleShot(0, lambda link=initial_link: self._start_happ_import(link, "startup"))

    def _build_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("root")
        self.setCentralWidget(root)
        root.setAcceptDrops(True)

        main = QVBoxLayout(root)
        main.setContentsMargins(12, 8, 12, 10)
        main.setSpacing(0)

        phone_shell = QFrame()
        phone_shell.setObjectName("phoneShell")
        phone_layout = QVBoxLayout(phone_shell)
        phone_layout.setContentsMargins(0, 0, 0, 0)
        phone_layout.setSpacing(10)

        header = QFrame()
        header.setObjectName("headerCard")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(6, 8, 6, 12)
        header_layout.setSpacing(8)
        logo = QLabel()
        logo.setPixmap(self._app_icon.pixmap(QSize(28, 28)))
        header_layout.addWidget(logo)
        title = QLabel('ambox')
        title.setObjectName('panelTitle')
        header_layout.addWidget(title)
        header_layout.addStretch(1)
        brand_caption = QLabel('VPN  ·  Linux')
        brand_caption.setObjectName('brandHint')
        header_layout.addWidget(brand_caption)

        phone_layout.addWidget(header)

        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("contentStack")
        phone_layout.addWidget(self.content_stack, 1)

        connect_tab = QWidget()
        connect_layout = QVBoxLayout(connect_tab)
        connect_layout.setContentsMargins(4, 4, 4, 4)
        connect_layout.setSpacing(10)

        self.vpn_status_card = QFrame()
        self.vpn_status_card.setObjectName("statusCard")
        vpn_status_layout = QHBoxLayout(self.vpn_status_card)
        vpn_status_layout.setContentsMargins(12, 10, 12, 10)
        vpn_status_layout.setSpacing(8)

        self.status_dot = QLabel("●")
        self.status_dot.setObjectName("statusDot")
        vpn_status_layout.addWidget(self.status_dot)

        vpn_status_text = QVBoxLayout()
        vpn_status_text.setContentsMargins(0, 0, 0, 0)
        vpn_status_text.setSpacing(1)
        self.status_label = QLabel("Disconnected")
        self.status_label.setObjectName("statusLabel")
        vpn_status_text.addWidget(self.status_label)
        self.vpn_profile_label = QLabel("Добавьте подписку или конфиг")
        self.vpn_profile_label.setObjectName("softHint")
        self.vpn_profile_label.setWordWrap(True)
        vpn_status_text.addWidget(self.vpn_profile_label)
        vpn_status_layout.addLayout(vpn_status_text, 1)
        connect_layout.addWidget(self.vpn_status_card)

        connect_layout.addSpacing(0)

        self.connect_btn = QPushButton("Подключить")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setMinimumHeight(48)
        self.connect_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.connect_btn.setProperty("vpnState", "disconnected")
        self.connect_btn.clicked.connect(self.toggle_connection)
        connect_layout.addWidget(self.connect_btn)

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

        self.vpn_empty_frame = QFrame()
        self.vpn_empty_frame.setObjectName("subCard")
        vpn_empty_layout = QVBoxLayout(self.vpn_empty_frame)
        vpn_empty_layout.setContentsMargins(12, 12, 12, 12)
        vpn_empty_layout.setSpacing(8)
        vpn_empty_label = QLabel("Пока нет серверов.\nДобавьте подписку или импортируйте конфиг.")
        vpn_empty_label.setObjectName("emptyState")
        vpn_empty_label.setAlignment(Qt.AlignCenter)
        vpn_empty_label.setWordWrap(True)
        vpn_empty_layout.addWidget(vpn_empty_label)
        vpn_empty_buttons = QHBoxLayout()
        vpn_empty_buttons.setSpacing(8)
        vpn_add_sub_btn = QPushButton("Добавить подписку")
        vpn_add_sub_btn.clicked.connect(self.add_subscription_dialog)
        vpn_paste_btn = QPushButton("Из буфера")
        vpn_paste_btn.clicked.connect(self.import_from_clipboard)
        vpn_empty_buttons.addWidget(vpn_add_sub_btn)
        vpn_empty_buttons.addWidget(vpn_paste_btn)
        vpn_empty_layout.addLayout(vpn_empty_buttons)
        self.vpn_empty_frame.setVisible(False)
        connect_layout.addWidget(self.vpn_empty_frame)

        connect_layout.addSpacing(0)

        self.quick_profile_frame = QFrame()
        self.quick_profile_frame.setObjectName("quickProfileCard")
        quick_profile_layout = QVBoxLayout(self.quick_profile_frame)
        quick_profile_layout.setContentsMargins(12, 10, 12, 10)
        quick_profile_layout.setSpacing(6)

        quick_profile_label = QLabel("Выберите сервер")
        quick_profile_label.setObjectName("quickProfileTitle")
        quick_profile_layout.addWidget(quick_profile_label)
        quick_profile_row = QHBoxLayout()
        quick_profile_row.setSpacing(7)

        self.quick_profile_combo = QComboBox()
        self.quick_profile_combo.setObjectName("quickProfileCombo")
        self.quick_profile_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.quick_profile_combo.setMinimumContentsLength(14)
        quick_profile_row.addWidget(self.quick_profile_combo, 1)

        self.quick_profile_latency_label = QLabel("Latency update: never")
        self.quick_profile_latency_label.setObjectName("softHint")
        self.quick_profile_latency_label.hide()

        self.fastest_btn = QPushButton("Лучший")
        self.fastest_btn.setToolTip("Connect to the highest-quality available profile (Ctrl+F)")
        self.fastest_btn.clicked.connect(self._connect_fastest)
        quick_profile_row.addWidget(self.fastest_btn)
        quick_profile_layout.addLayout(quick_profile_row)

        self.quick_profile_frame.setVisible(False)
        connect_layout.addWidget(self.quick_profile_frame)

        self.app_quick_btn = QPushButton('Приложения  ·  Весь трафик')
        self.app_quick_btn.setObjectName('quickLink')
        self.app_quick_btn.setToolTip('Выбрать, какие приложения использовать через VPN')
        self.app_quick_btn.clicked.connect(lambda: self._set_bottom_page(3))
        connect_layout.addWidget(self.app_quick_btn)

        self.traffic_card = QFrame()
        self.traffic_card.setObjectName('metricCard')
        traffic_layout = QVBoxLayout(self.traffic_card)
        traffic_layout.setContentsMargins(12, 11, 12, 10)
        traffic_layout.setSpacing(6)
        traffic_header = QHBoxLayout()
        traffic_title = QLabel('ТРАФИК В РЕАЛЬНОМ ВРЕМЕНИ')
        traffic_title.setObjectName('fieldLabel')
        traffic_header.addWidget(traffic_title)
        traffic_header.addStretch(1)
        self.traffic_label = QLabel('↓ 0 B/s     ↑ 0 B/s')
        self.traffic_label.setObjectName('trafficRate')
        traffic_header.addWidget(self.traffic_label)
        traffic_layout.addLayout(traffic_header)
        self.traffic_chart = TrafficChart(self.traffic_card)
        self.traffic_chart.setFixedHeight(102)
        traffic_layout.addWidget(self.traffic_chart)
        quality_row = QHBoxLayout()
        self.quality_status_label = QLabel('Ожидаем измерений')
        self.quality_status_label.setObjectName('softHint')
        quality_row.addWidget(self.quality_status_label, 1)
        health_btn = QPushButton('Диагностика')
        health_btn.clicked.connect(lambda: (self._set_bottom_page(5), self.run_diagnostics()))
        quality_row.addWidget(health_btn)
        traffic_layout.addLayout(quality_row)
        connect_layout.addWidget(self.traffic_card)
        overview_scroll = QScrollArea()
        overview_scroll.setWidgetResizable(True)
        overview_scroll.setFrameShape(QFrame.NoFrame)
        overview_scroll.setWidget(connect_tab)
        self.content_stack.addWidget(overview_scroll)

        profiles_tab = QWidget()
        profiles_layout = QVBoxLayout(profiles_tab)
        profiles_layout.setContentsMargins(4, 6, 4, 4)
        profiles_layout.setSpacing(9)

        profiles_title = QLabel("Конфиги")
        profiles_title.setObjectName("sectionTitle")
        profiles_layout.addWidget(profiles_title)

        source_row = QHBoxLayout()
        source_row.setSpacing(6)
        self.manual_source_btn = QPushButton("Мои конфиги")
        self.sub_source_btn = QPushButton("Из подписок")
        for button in (self.manual_source_btn, self.sub_source_btn):
            button.setObjectName("sourceTab")
            button.setCheckable(True)
            button.setMinimumHeight(36)
            source_row.addWidget(button, 1)
        self.manual_source_btn.setChecked(True)
        profiles_layout.addLayout(source_row)

        self.profile_latency_label = QLabel("Latency update: never")
        self.profile_latency_label.setObjectName("softHint")
        profiles_layout.addWidget(self.profile_latency_label)

        profile_tools = QHBoxLayout()
        profile_tools.setSpacing(8)

        self.profile_search_edit = QLineEdit()
        self.profile_search_edit.setObjectName("profileSearch")
        self.profile_search_edit.setPlaceholderText("Поиск серверов")
        profile_tools.addWidget(self.profile_search_edit, 1)

        self.profile_sort_combo = QComboBox()
        self.profile_sort_combo.addItem("Мой порядок", "manual")
        self.profile_sort_combo.addItem("Название", "name")
        self.profile_sort_combo.addItem("Задержка", "latency")
        self.profile_sort_combo.addItem("Страна", "location")
        self.profile_sort_combo.addItem("Недавние", "recent")
        self.profile_sort_combo.addItem('Избранные', 'favorites')
        self.profile_sort_combo.addItem('Качество', 'quality')
        profile_tools.addWidget(self.profile_sort_combo)
        profiles_layout.addLayout(profile_tools)

        profile_filters = QHBoxLayout()
        profile_filters.setSpacing(8)

        self.profile_location_combo = QComboBox()
        self.profile_location_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.profile_location_combo.setMinimumContentsLength(14)
        self.profile_location_combo.addItem("🌍 Все страны", "ALL")
        profile_filters.addWidget(self.profile_location_combo, 1)

        self.ping_btn = QPushButton("Проверить")
        self.ping_btn.setToolTip("Test latency of all profiles in parallel (Ctrl+P)")
        self.ping_btn.clicked.connect(self.refresh_latencies)
        profile_filters.addWidget(self.ping_btn)

        profiles_layout.addLayout(profile_filters)

        source_actions = QHBoxLayout()
        source_actions.setSpacing(7)
        self.import_btn = QPushButton("+ Импорт")
        self.import_btn.setObjectName("primaryAction")
        self.import_btn.clicked.connect(self.import_config)
        source_actions.addWidget(self.import_btn)
        self.clip_btn = QPushButton("Вставить")
        self.clip_btn.clicked.connect(self.import_from_clipboard)
        source_actions.addWidget(self.clip_btn)
        self.update_subs_btn = QPushButton("Обновить")
        self.update_subs_btn.clicked.connect(lambda: self.update_all_subscriptions(silent=False))
        source_actions.addWidget(self.update_subs_btn)
        self.manage_subs_btn = QPushButton("Подписки")
        self.manage_subs_btn.clicked.connect(self.show_subscriptions_dialog)
        source_actions.addWidget(self.manage_subs_btn)
        source_actions.addStretch(1)
        profiles_layout.addLayout(source_actions)

        self.subs_filter_row = QWidget()
        subs_filter_layout = QHBoxLayout(self.subs_filter_row)
        subs_filter_layout.setContentsMargins(0, 0, 0, 0)
        subs_filter_layout.setSpacing(8)
        subs_filter_label = QLabel("Источник:")
        subs_filter_label.setObjectName("softHint")
        subs_filter_layout.addWidget(subs_filter_label)
        self.subs_filter_combo = QComboBox()
        self.subs_filter_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.subs_filter_combo.setMinimumContentsLength(14)
        self.subs_filter_combo.setToolTip("Показать серверы выбранной подписки")
        subs_filter_layout.addWidget(self.subs_filter_combo, 1)
        self.subs_filter_row.setVisible(False)
        profiles_layout.addWidget(self.subs_filter_row)

        self.profiles_empty_label = QLabel()
        self.profiles_empty_label.setObjectName("emptyState")
        self.profiles_empty_label.setAlignment(Qt.AlignCenter)
        self.profiles_empty_label.setWordWrap(True)
        self.profiles_empty_label.setVisible(False)
        profiles_layout.addWidget(self.profiles_empty_label)

        self.profile_list = ProfileListWidget()
        self.profile_list.setObjectName("profiles")
        self.profile_list.setContextMenuPolicy(Qt.CustomContextMenu)
        profiles_layout.addWidget(self.profile_list, 1)

        self.profile_list_hint = QLabel("Двойной клик — подключиться · перетащите файл для импорта")
        self.profile_list_hint.setObjectName("softHint")
        self.profile_list_hint.setWordWrap(True)
        profiles_layout.addWidget(self.profile_list_hint)

        profile_buttons = QHBoxLayout()
        profile_buttons.setSpacing(8)
        export_btn = QPushButton("Экспорт")
        export_btn.clicked.connect(self.export_selected_profile)
        self.delete_profile_btn = QPushButton("Удалить конфиг")
        self.delete_profile_btn.clicked.connect(self.delete_selected_profile)
        profile_buttons.addStretch(1)
        profile_buttons.addWidget(export_btn)
        profile_buttons.addWidget(self.delete_profile_btn)
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
        settings_body.setObjectName("settingsBody")
        settings_layout = QVBoxLayout(settings_body)
        settings_layout.setContentsMargins(10, 10, 10, 10)
        settings_layout.setSpacing(10)
        settings_layout.setAlignment(Qt.AlignTop)

        settings_title = QLabel("Routing")
        settings_title.setObjectName("sectionTitle")
        settings_layout.addWidget(settings_title)

        perf_card = QFrame()
        perf_card.setObjectName("subCard")
        perf_layout = QVBoxLayout(perf_card)
        perf_layout.setContentsMargins(10, 10, 10, 10)
        perf_layout.setSpacing(8)

        perf_label = QLabel("Connection")
        perf_label.setObjectName("fieldLabel")
        self.auto_switch_checkbox = QCheckBox("Smart Connect (quality + availability)")
        self.auto_update_subs_checkbox = QCheckBox("Update subscriptions on startup")
        self.auto_update_subs_checkbox.setChecked(True)
        self.auto_reconnect_checkbox = QCheckBox('Reconnect automatically after unexpected disconnect')
        self.auto_reconnect_checkbox.setChecked(True)
        perf_layout.addWidget(perf_label)
        perf_layout.addWidget(self.auto_switch_checkbox)
        perf_layout.addWidget(self.auto_reconnect_checkbox)
        perf_layout.addWidget(self.auto_update_subs_checkbox)

        update_interval = QHBoxLayout()
        interval_label = QLabel('Auto-update subscriptions every')
        interval_label.setObjectName('softHint')
        update_interval.addWidget(interval_label)
        self.sub_update_hours_spin = QSpinBox()
        self.sub_update_hours_spin.setRange(1, 168)
        self.sub_update_hours_spin.setValue(12)
        self.sub_update_hours_spin.setSuffix(' h')
        update_interval.addWidget(self.sub_update_hours_spin)
        perf_layout.addLayout(update_interval)

        timeout_host = QWidget()
        timeout_row = QHBoxLayout(timeout_host)
        timeout_row.setContentsMargins(0, 0, 0, 0)
        timeout_row.setSpacing(8)
        timeout_desc = QLabel("Latency timeout")
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

        preset_label = QLabel('One-click routing presets')
        preset_label.setObjectName('fieldLabel')
        settings_layout.addWidget(preset_label)
        preset_row = QHBoxLayout()
        self.preset_combo = QComboBox()
        for key, (label, _domains) in PRESETS.items():
            self.preset_combo.addItem(label, key)
        preset_row.addWidget(self.preset_combo, 1)
        preset_btn = QPushButton('Apply preset')
        preset_btn.clicked.connect(self._apply_route_preset)
        preset_row.addWidget(preset_btn)
        settings_layout.addLayout(preset_row)
        self.advanced_checkbox = QCheckBox('Show advanced routing & DNS options')
        settings_layout.addWidget(self.advanced_checkbox)

        route_label = QLabel('Routing mode')
        route_label.setObjectName('fieldLabel')
        self.route_mode_combo = QComboBox()
        self.route_mode_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.route_mode_combo.setMinimumContentsLength(16)
        self.route_mode_combo.addItem("Proxy everything", "all")
        self.route_mode_combo.addItem("Proxy selected domains/IPs", "only_selected")
        self.route_mode_combo.addItem("Proxy everything except selected", "all_except_selected")
        settings_layout.addWidget(route_label)
        settings_layout.addWidget(self.route_mode_combo)

        self.routing_mode_hint = QLabel("Add one domain or IP per line.")
        self.routing_mode_hint.setWordWrap(True)
        self.routing_mode_hint.setObjectName("softHint")
        settings_layout.addWidget(self.routing_mode_hint)

        self.ignore_ru_domains_checkbox = QCheckBox("Bypass .ru domains")
        settings_layout.addWidget(self.ignore_ru_domains_checkbox)

        self.routing_domains_frame = QFrame()
        self.routing_domains_frame.setObjectName("subCard")
        routing_layout = QVBoxLayout(self.routing_domains_frame)
        routing_layout.setContentsMargins(10, 10, 10, 10)
        routing_layout.setSpacing(8)

        self.include_subdomains_checkbox = QCheckBox("Include subdomains")
        self.include_subdomains_checkbox.setChecked(True)
        routing_layout.addWidget(self.include_subdomains_checkbox)

        self.domains_edit = QPlainTextEdit()
        self.domains_edit.setObjectName("domains")
        self.domains_edit.setPlaceholderText("example.com\nyoutube.com\n203.0.113.0/24")
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
        self.dns_mode_combo.addItem("DNS through proxy", "proxy")
        self.dns_mode_combo.addItem("DNS direct", "direct")
        self.dns_mode_combo.addItem("Custom DNS", "custom")
        settings_layout.addWidget(dns_label)
        settings_layout.addWidget(self.dns_mode_combo)

        self.custom_dns_frame = QFrame()
        self.custom_dns_frame.setObjectName("subCard")
        custom_dns_layout = QVBoxLayout(self.custom_dns_frame)
        custom_dns_layout.setContentsMargins(10, 10, 10, 10)
        custom_dns_layout.setSpacing(6)

        custom_dns_label = QLabel("DNS address")
        custom_dns_label.setObjectName("fieldLabel")
        self.custom_dns_edit = QLineEdit()
        self.custom_dns_edit.setObjectName("customDns")
        self.custom_dns_edit.setPlaceholderText("1.1.1.1 or dns.google")
        custom_dns_layout.addWidget(custom_dns_label)
        custom_dns_layout.addWidget(self.custom_dns_edit)

        self.custom_dns_hint = QLabel("IP or host, for example 1.1.1.1")
        self.custom_dns_hint.setObjectName("softHint")
        custom_dns_layout.addWidget(self.custom_dns_hint)
        settings_layout.addWidget(self.custom_dns_frame)

        self.auto_redirect_checkbox = QCheckBox('Linux TUN auto_redirect (nftables)')
        self.auto_redirect_checkbox.setToolTip('Improves Linux routing and DNS interception; needs nftables and net-admin permission.')
        settings_layout.addWidget(self.auto_redirect_checkbox)
        leak_hint = QLabel('Important: strict routing and auto_redirect are NOT a system-wide kill switch. '
                           'Direct/bypass rules can still leave the VPN.')
        leak_hint.setObjectName('softHint')
        leak_hint.setWordWrap(True)
        settings_layout.addWidget(leak_hint)
        self._advanced_widgets = [route_label, self.route_mode_combo,
                                  self.routing_mode_hint, self.ignore_ru_domains_checkbox,
                                  self.routing_domains_frame, dns_label, self.dns_mode_combo,
                                  self.custom_dns_frame, self.auto_redirect_checkbox, leak_hint]
        settings_layout.addStretch(1)

        settings_scroll.setWidget(settings_body)
        settings_tab_layout.addWidget(settings_scroll)
        self.content_stack.addWidget(settings_tab)

        applications_tab = QWidget()
        applications_layout = QVBoxLayout(applications_tab)
        applications_layout.setContentsMargins(5, 6, 5, 4)
        applications_layout.setSpacing(10)

        title_row = QHBoxLayout()
        applications_title = QLabel('Приложения')
        applications_title.setObjectName('sectionTitle')
        title_row.addWidget(applications_title)
        title_row.addStretch(1)
        back_to_vpn = QPushButton('На главную')
        back_to_vpn.clicked.connect(lambda: self._set_bottom_page(0))
        title_row.addWidget(back_to_vpn)
        applications_layout.addLayout(title_row)

        intro = QLabel('Какие программы должны использовать VPN?')
        intro.setObjectName('softHint')
        intro.setWordWrap(True)
        applications_layout.addWidget(intro)

        # Keep the QComboBox as the existing source of truth / persisted mode,
        # but expose an unambiguous three-way control instead of a dropdown.
        self.app_mode_combo = QComboBox(applications_tab)
        self.app_mode_combo.addItem('Обычный режим', 'disabled')
        self.app_mode_combo.addItem('Только выбранные', 'proxy_selected')
        self.app_mode_combo.addItem('Все, кроме выбранных', 'direct_selected')
        self.app_mode_combo.hide()
        app_modes = QHBoxLayout()
        app_modes.setSpacing(6)
        self.app_mode_buttons: dict[str, QPushButton] = {}
        for label, mode in [
            ('Обычно', 'disabled'),
            ('Только выбранные', 'proxy_selected'),
            ('Кроме выбранных', 'direct_selected'),
        ]:
            button = QPushButton(label)
            button.setObjectName('appModeBtn')
            button.setCheckable(True)
            button.setMinimumHeight(39)
            button.clicked.connect(lambda _checked=False, key=mode: self._select_app_mode(key))
            app_modes.addWidget(button, 1)
            self.app_mode_buttons[mode] = button
        applications_layout.addLayout(app_modes)
        self.app_mode_explanation = QLabel('')
        self.app_mode_explanation.setObjectName('appModeHint')
        self.app_mode_explanation.setWordWrap(True)
        self.app_mode_explanation.setMinimumHeight(34)
        applications_layout.addWidget(self.app_mode_explanation)

        list_header = QHBoxLayout()
        list_header.setSpacing(8)
        self.app_search_edit = QLineEdit()
        self.app_search_edit.setObjectName('appSearch')
        self.app_search_edit.setPlaceholderText('Найти приложение…')
        self.app_search_edit.setClearButtonEnabled(True)
        self.app_search_edit.textChanged.connect(self._filter_application_list)
        list_header.addWidget(self.app_search_edit, 1)
        self.app_source_combo = QComboBox()
        self.app_source_combo.addItem('Все', 'all')
        self.app_source_combo.addItem('Запущенные', 'running')
        self.app_source_combo.addItem('Выбранные', 'selected')
        self.app_source_combo.currentIndexChanged.connect(self._filter_application_list)
        self.app_source_combo.setMinimumContentsLength(11)
        list_header.addWidget(self.app_source_combo)
        applications_layout.addLayout(list_header)

        self.application_list = QListWidget()
        self.application_list.setObjectName('applications')
        self.application_list.setSelectionMode(QAbstractItemView.NoSelection)
        self.application_list.setIconSize(QSize(30, 30))
        self.application_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.application_list.setWordWrap(False)
        self.application_list.setAlternatingRowColors(False)
        applications_layout.addWidget(self.application_list, 1)

        tools = QHBoxLayout()
        tools.setSpacing(7)
        self.app_selection_label = QLabel('Не выбрано')
        self.app_selection_label.setObjectName('softHint')
        tools.addWidget(self.app_selection_label, 1)
        self.refresh_apps_btn = QPushButton('Обновить список')
        self.refresh_apps_btn.clicked.connect(self._rescan_application_catalog)
        tools.addWidget(self.refresh_apps_btn)
        self.add_app_btn = QPushButton('+ Файл')
        self.add_app_btn.setToolTip('Добавить программу по пути к исполняемому файлу')
        self.add_app_btn.clicked.connect(self._add_application_executable)
        tools.addWidget(self.add_app_btn)
        applications_layout.addLayout(tools)

        hint_card = QFrame()
        hint_card.setObjectName('appNotice')
        hint_layout = QVBoxLayout(hint_card)
        hint_layout.setContentsMargins(11, 9, 11, 9)
        self.app_warning = QLabel(
            'Linux определяет приложения по исполняемому файлу. Для Flatpak и '
            'программ с отдельными сетевыми процессами сначала запустите программу '
            'и нажмите «Обновить список». DNS системы общий; это не Kill Switch.')
        self.app_warning.setObjectName('softHint')
        self.app_warning.setWordWrap(True)
        hint_layout.addWidget(self.app_warning)
        applications_layout.addWidget(hint_card)

        self._refresh_application_list()
        self.content_stack.addWidget(applications_tab)

        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.setContentsMargins(10, 10, 10, 10)
        logs_layout.setSpacing(8)

        logs_title = QLabel("Connection logs")
        logs_title.setObjectName("sectionTitle")
        logs_title_row = QHBoxLayout()
        logs_title_row.addWidget(logs_title)
        logs_title_row.addStretch(1)
        logs_back_btn = QPushButton("Back")
        logs_back_btn.clicked.connect(lambda: self._set_bottom_page(0))
        logs_title_row.addWidget(logs_back_btn)
        logs_layout.addLayout(logs_title_row)

        log_buttons = QHBoxLayout()
        log_buttons.setSpacing(8)
        self.copy_logs_btn = QPushButton("Copy logs")
        self.clear_logs_btn = QPushButton("Clear logs")
        self.open_log_file_btn = QPushButton("Open log file")
        log_buttons.addWidget(self.copy_logs_btn)
        log_buttons.addWidget(self.clear_logs_btn)
        log_buttons.addWidget(self.open_log_file_btn)
        logs_layout.addLayout(log_buttons)

        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setMaximumBlockCount(600)
        self.logs.setObjectName("logs")
        logs_layout.addWidget(self.logs, 1)
        self.content_stack.addWidget(logs_tab)

        diagnostics_tab = QWidget()
        diagnostics_layout = QVBoxLayout(diagnostics_tab)
        diagnostics_layout.setContentsMargins(12, 12, 12, 12)
        diagnostics_layout.setSpacing(12)
        diagnostic_title = QLabel('Connection diagnostics')
        diagnostic_title.setObjectName('sectionTitle')
        diagnostics_layout.addWidget(diagnostic_title)
        diagnostic_hint = QLabel('Checks run on demand only while a TUN exists. With split tunneling, '
                                 'external probes may follow a direct route. This is not a leak test or kill switch.')
        diagnostic_hint.setObjectName('softHint')
        diagnostic_hint.setWordWrap(True)
        diagnostics_layout.addWidget(diagnostic_hint)
        self.diagnostic_summary = QLabel('Not checked yet')
        self.diagnostic_summary.setObjectName('diagnosticSummary')
        self.diagnostic_summary.setWordWrap(True)
        diagnostics_layout.addWidget(self.diagnostic_summary)
        diag_actions = QHBoxLayout()
        self.diag_run_btn = QPushButton('Run diagnostics')
        self.diag_run_btn.clicked.connect(self.run_diagnostics)
        diag_actions.addWidget(self.diag_run_btn)
        diag_export_btn = QPushButton('Copy safe report')
        diag_export_btn.clicked.connect(self.copy_diagnostic_report)
        diag_actions.addWidget(diag_export_btn)
        diag_actions.addStretch(1)
        diagnostics_layout.addLayout(diag_actions)
        self.diag_details = QPlainTextEdit()
        self.diag_details.setReadOnly(True)
        self.diag_details.setObjectName('logs')
        self.diag_details.setPlaceholderText('Status, tunnel, DNS, public IP, RTT and process memory will appear here.')
        diagnostics_layout.addWidget(self.diag_details, 1)
        self.content_stack.addWidget(diagnostics_tab)

        self.subscriptions_panel = SubscriptionsPanel(self)
        self.content_stack.addWidget(self.subscriptions_panel)  # index 6

        bottom_nav = QFrame()
        bottom_nav.setObjectName("bottomNav")
        self.bottom_nav = bottom_nav
        nav_layout = QHBoxLayout(bottom_nav)
        nav_layout.setContentsMargins(5, 5, 5, 5)
        nav_layout.setSpacing(3)
        self.nav_buttons: list[QPushButton] = []
        self._mobile_pages = [0, 1, 6]
        for index, label in enumerate(["VPN", "Конфиги", "Подписки"]):
            btn = QPushButton(label)
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _checked=False, i=index: self._set_bottom_page(self._mobile_pages[i]))
            nav_layout.addWidget(btn, 1)
            self.nav_buttons.append(btn)
        self.more_btn = QPushButton("Ещё")
        self.more_btn.setObjectName("navBtn")
        self.more_btn.setToolTip("Маршруты, приложения, диагностика и логи")
        more_menu = QMenu(self.more_btn)
        for label, page in [("Маршрутизация", 2), ("Приложения", 3),
                            ("Диагностика", 5), ("Логи", 4)]:
            action = more_menu.addAction(label)
            action.triggered.connect(lambda _checked=False, i=page: self._set_bottom_page(i))
        self.more_btn.setMenu(more_menu)
        nav_layout.addWidget(self.more_btn)
        phone_layout.addWidget(bottom_nav)
        self._set_bottom_page(0)
        main.addWidget(phone_shell, 1)
        for key, page in [("Ctrl+1", 0), ("Ctrl+2", 1), ("Ctrl+3", 6)]:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.setContext(Qt.ApplicationShortcut)
            shortcut.activated.connect(lambda i=page: self._set_bottom_page(i))
        fastest_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        fastest_shortcut.setContext(Qt.ApplicationShortcut)
        fastest_shortcut.activated.connect(self._connect_fastest)

        self.statusBar().hide()  # status lives in the dashboard; no redundant bottom bar

        self.setStyleSheet(STYLESHEET)

    def _setup_notifications(self) -> None:
        self.tray_icon: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self._app_icon)
        self.tray_icon.setToolTip("ambox")
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_menu = QMenu(self)
        self.tray_toggle_action = self.tray_menu.addAction('Connect')
        self.tray_toggle_action.triggered.connect(self.toggle_connection)
        self.tray_profiles_menu = self.tray_menu.addMenu('Switch server')
        self.tray_menu.addSeparator()
        diagnostics_action = self.tray_menu.addAction('Diagnostics')
        diagnostics_action.triggered.connect(lambda: (self._bring_to_front(), self._set_bottom_page(5)))
        show_action = self.tray_menu.addAction('Open ambox')
        show_action.triggered.connect(self._bring_to_front)
        exit_action = self.tray_menu.addAction('Quit')
        exit_action.triggered.connect(self.close)
        self.tray_icon.setContextMenu(self.tray_menu)
        self._update_tray_menu()
        self.tray_icon.show()

    def _build_app_icon(self) -> QIcon:
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#111621"))
        painter.drawRoundedRect(4, 4, 56, 56, 16, 16)

        painter.setBrush(QColor("#31c9ae"))
        painter.drawRoundedRect(10, 10, 44, 44, 14, 14)

        painter.setBrush(QColor("#171b26"))
        painter.drawEllipse(18, 18, 28, 28)

        pen = QPen(QColor("#e6fffa"))
        pen.setWidth(3)
        painter.setPen(pen)
        painter.drawArc(17, 17, 30, 30, 35 * 16, 240 * 16)

        painter.setPen(QColor("#171b26"))
        font = QFont("Noto Sans", 16)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "A")

        painter.end()
        return QIcon(pixmap)

    def _bring_to_front(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()
        self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in {QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick}:
            self._bring_to_front()

    def _update_tray_menu(self) -> None:
        if getattr(self, 'tray_icon', None) is None:
            return
        connected = self.vpn.status in {'connected', 'connecting', 'disconnecting'}
        self.tray_toggle_action.setText('Disconnect' if connected else 'Connect')
        self.tray_icon.setToolTip(f'ambox • {self.vpn.status}')
        self.tray_profiles_menu.clear()
        indices = sorted(range(len(self.profiles)),
                         key=lambda i: (self.profiles[i].id not in self.favorite_profile_ids,
                                        self.profiles[i].name.lower()))[:40]
        for idx in indices:
            profile = self.profiles[idx]
            prefix = '★ ' if profile.id in self.favorite_profile_ids else ''
            action = self.tray_profiles_menu.addAction(prefix + profile.name)
            action.setCheckable(True)
            action.setChecked(idx == self.connected_index and connected)
            action.triggered.connect(lambda _checked=False, i=idx: self._connect_profile(i))
        self.tray_profiles_menu.setEnabled(bool(indices))

    def _setup_instance_server(self) -> None:
        """Serve second-instance launches: show window / import their link."""
        try:
            QLocalServer.removeServer(SERVER_NAME)  # stale socket from a crash
            server = QLocalServer(self)
            if not server.listen(SERVER_NAME):
                logging.warning("Single-instance server failed: %s", server.errorString())
                return
            server.newConnection.connect(self._on_instance_connection)
            self._instance_server = server
        except Exception as exc:
            logging.warning("Single-instance server unavailable: %s", exc)

    def _on_instance_connection(self) -> None:
        server = self._instance_server
        if server is None:
            return
        sock = server.nextPendingConnection()
        if sock is None:
            return
        try:
            sock.waitForReadyRead(1000)
            message = bytes(sock.readAll()).decode("utf-8", errors="replace")
        except Exception:
            message = ""
        finally:
            sock.disconnectFromServer()
            sock.deleteLater()
        self._bring_to_front()
        if message.startswith(LINK_PREFIX):
            link = message[len(LINK_PREFIX):].strip()
            if link:
                self._start_happ_import(link, "second instance")

    def _setup_sleep_monitor(self) -> None:
        """Reconnect the tunnel after system suspend via systemd-logind D-Bus."""
        try:
            from PySide6.QtDBus import QDBusConnection
        except ImportError:
            logging.debug("QtDBus unavailable; suspend/resume monitoring disabled")
            return
        try:
            bus = QDBusConnection.systemBus()
            if bus.isConnected() and bus.connect(
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                self._on_prepare_for_sleep,
            ):
                logging.info("Suspend/resume monitoring enabled (logind D-Bus)")
                return
            logging.debug("logind D-Bus unavailable; suspend/resume monitoring disabled")
        except Exception as exc:
            logging.debug("Suspend/resume monitoring disabled: %s", exc)

    def _on_prepare_for_sleep(self, sleeping: bool) -> None:
        if sleeping:
            self._sleep_was_connected = self.vpn.status == "connected"
            self._sleep_connected_index = self.connected_index
            if self._sleep_was_connected:
                self._append_log("System is going to sleep; VPN state saved")
            return
        if not self._sleep_was_connected:
            return
        self._sleep_was_connected = False
        self._append_log("System resumed; verifying VPN tunnel...")
        QTimer.singleShot(2500, self._verify_after_resume)

    def _verify_after_resume(self) -> None:
        index = self._sleep_connected_index
        if index is None or index >= len(self.profiles):
            return
        if self.vpn.status != "connected":
            self._append_log("VPN session did not survive suspend; reconnecting...")
            self._connect_profile(index)
            return
        threading.Thread(target=self._resume_probe_worker, daemon=True).start()

    def _resume_probe_worker(self) -> None:
        res = probe_active_connection(timeout_sec=4.0)
        self.resume_probe_finished.emit(bool(res and res.get("ok")))

    def _on_resume_probe_finished(self, ok: bool) -> None:
        if ok:
            self._append_log("VPN tunnel survived suspend")
            return
        index = self._sleep_connected_index
        if index is None or index >= len(self.profiles):
            return
        if self.vpn.status != "connected":
            return  # already reconnecting or stopped by the user
        self._append_log("VPN tunnel is dead after resume; reconnecting...")
        self._connect_profile(index)

    def _notify_user(self, title: str, message: str) -> None:
        if self.tray_icon is not None:
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 3000)

    def _set_bottom_page(self, index: int) -> None:
        if not 0 <= index < self.content_stack.count():
            return
        self.content_stack.setCurrentIndex(index)
        for page, button in zip(self._mobile_pages, self.nav_buttons):
            button.setChecked(page == index)
        self.more_btn.setProperty("active", index not in self._mobile_pages)
        self.more_btn.style().unpolish(self.more_btn)
        self.more_btn.style().polish(self.more_btn)
        if index == 6:
            self.subscriptions_panel.refresh_list()

    def _set_profile_source(self, source: str, sub_id: str = "") -> None:
        if source not in {"manual", "subscriptions"}:
            return
        self._profile_source = source
        self._selected_sub_id = sub_id if source == "subscriptions" else ""
        self.settings.setValue("ui/config_source", source)
        self.manual_source_btn.setChecked(source == "manual")
        self.sub_source_btn.setChecked(source == "subscriptions")
        self._selected_location = "ALL"
        self._refresh_profile_views(preserve_selection=False)

    def _show_subscription_nodes(self, sub_id: str) -> None:
        if not self.subscription_store.get(sub_id):
            return
        self._set_profile_source("subscriptions", sub_id)
        self._set_bottom_page(1)

    def _profile_item_text(self, index: int) -> str:
        profile = self.profiles[index]
        latency = self.profile_latencies[index] if index < len(self.profile_latencies) else None
        if index in self._pending_latency_indices or not self._latency_has_results:
            suffix = "checking..."
        else:
            suffix = "timeout" if latency is None else f"{latency} ms"
        usage = self.profile_usage_bytes[index] if index < len(self.profile_usage_bytes) else 0
        connected = '● ' if self.connected_index == index and self.vpn.status in {'connected', 'connecting'} else ''
        favorite = '★ ' if profile.id in self.favorite_profile_ids else ''
        srv = str(profile.outbound.get("server") or "")
        loc = detect_location(profile.name, srv)
        flag_prefix = f"{loc.flag} " if loc.flag and loc.flag not in profile.name else ""
        quality = self.quality.quality(profile.id)
        q_text = f' · Q{quality.score:.0f}' if quality and quality.samples >= 3 else ''
        return f'{connected}{favorite}{flag_prefix}{profile.name}  [{suffix}{q_text} | {self._format_bytes(usage)}]'

    def _profile_usage_key(self, profile: Profile) -> str:
        return profile.id

    def _legacy_profile_usage_key(self, profile: Profile) -> str:
        """Read old settings once, then discard plaintext credential-bearing keys."""
        try:
            return json.dumps(profile.outbound, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        except (TypeError, ValueError):
            return profile.name

    def _profile_signature(self, profile: Profile) -> str:
        outbound = {k: v for k, v in profile.outbound.items() if k != 'tag'}
        data = json.dumps(outbound, sort_keys=True, default=str, ensure_ascii=True)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _profile_last_used_key(self, profile: Profile) -> str:
        return profile.id

    def _migrate_profile_metadata(self, loaded: list[Profile]) -> bool:
        old_usage, old_last = self._usage_store, self._last_used_store
        new_usage: dict[str, int] = {}
        new_last: dict[str, float] = {}
        for profile in loaded:
            legacy_key = self._legacy_profile_usage_key(profile)
            new_usage[profile.id] = max(0, int(old_usage.get(profile.id, old_usage.get(legacy_key, 0))))
            timestamp = float(old_last.get(profile.id, old_last.get(legacy_key, 0.0)))
            if timestamp > 0:
                new_last[profile.id] = timestamp
        dirty = new_usage != old_usage or new_last != old_last
        self._usage_store, self._last_used_store = new_usage, new_last
        if dirty:
            self._usage_dirty = True
            self._persist_usage_store(force=True)
            self._persist_last_used_store()
        return dirty

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

    def _read_interface_counters(self, interface: str = IFACE_NAME) -> tuple[int, int] | None:
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
        self._protect_settings_file()
        self._usage_dirty = False
        self._last_usage_persist = now

    def _persist_last_used_store(self) -> None:
        self.settings.setValue("profile_last_used", json.dumps(self._last_used_store, ensure_ascii=True))
        self.settings.sync()
        self._protect_settings_file()

    def _protect_settings_file(self) -> None:
        """Harden settings migrated from older versions (possibly 0644)."""
        path = settings_path()
        ensure_user_owned(path)
        if os.name == 'posix' and path.exists():
            try:
                path.chmod(0o600)
            except OSError:
                pass

    def _touch_profile_last_used(self, index: int) -> None:
        if index < 0 or index >= len(self.profiles):
            return
        key = self._profile_last_used_key(self.profiles[index])
        self._last_used_store[key] = time.time()
        self._persist_last_used_store()

    def _profile_last_used_timestamp(self, index: int) -> float:
        if index < 0 or index >= len(self.profiles):
            return 0.0
        return float(self._last_used_store.get(self._profile_last_used_key(self.profiles[index]), 0.0))

    def _refresh_latency_update_labels(self) -> None:
        text = f"Latency update: {self._last_latency_update_text}"
        self.profile_latency_label.setText(text)
        self.quick_profile_latency_label.setText(text)

    def _sorted_profile_indices(self) -> list[int]:
        indices = list(range(len(self.profiles)))
        search_text = self.profile_search_edit.text().strip().lower()
        if search_text:
            indices = [idx for idx in indices if search_text in self.profiles[idx].name.lower()]

        if self._selected_location != "ALL":
            filtered = []
            for idx in indices:
                p = self.profiles[idx]
                srv = str(p.outbound.get("server") or "")
                loc = detect_location(p.name, srv)
                if loc.code == self._selected_location:
                    filtered.append(idx)
            indices = filtered

        allowed = set(profile_indices_for_source(self.profiles, self._profile_source, self._selected_sub_id))
        indices = [idx for idx in indices if idx in allowed]

        sort_mode = str(self.profile_sort_combo.currentData() or "manual")
        if sort_mode == "name":
            indices.sort(key=lambda idx: self.profiles[idx].name.lower())
        elif sort_mode == "latency":
            indices.sort(
                key=lambda idx: (
                    self.profile_latencies[idx] is None,
                    self.profile_latencies[idx] if self.profile_latencies[idx] is not None else 10**9,
                    self.profiles[idx].name.lower(),
                )
            )
        elif sort_mode == "location":
            indices.sort(
                key=lambda idx: (
                    detect_location(self.profiles[idx].name, str(self.profiles[idx].outbound.get("server") or "")).name,
                    self.profiles[idx].name.lower(),
                )
            )
        elif sort_mode == "recent":
            indices.sort(key=lambda idx: (-self._profile_last_used_timestamp(idx), self.profiles[idx].name.lower()))
        elif sort_mode == 'favorites':
            indices.sort(key=lambda idx: (self.profiles[idx].id not in self.favorite_profile_ids,
                                          self.profiles[idx].name.lower()))
        elif sort_mode == 'quality':
            indices.sort(key=lambda idx: -(self.quality.quality(self.profiles[idx].id).score
                                           if self.quality.quality(self.profiles[idx].id) else 0))
        return indices

    def _set_selected_profile_index(self, profile_index: int | None) -> None:
        if profile_index is None:
            self.profile_list.clearSelection()
            self.profile_list.setCurrentRow(-1)
            return
        for row in range(self.profile_list.count()):
            item = self.profile_list.item(row)
            if item is None:
                continue
            if item.data(Qt.UserRole) == profile_index:
                self.profile_list.setCurrentRow(row)
                return

    def _update_profile_list_capabilities(self) -> None:
        manual_mode = str(self.profile_sort_combo.currentData() or "manual") == "manual"
        drag_enabled = (
            manual_mode
            and not self.profile_search_edit.text().strip()
            and self._selected_location == "ALL"
            and self._profile_source == "manual"
        )
        self.profile_list.setDragEnabled(drag_enabled)
        self.profile_list.setDragDropMode(QAbstractItemView.InternalMove if drag_enabled else QAbstractItemView.NoDragDrop)
        self.profile_list_hint.setText(
            "Перетаскивайте для сортировки · двойной клик для подключения" if drag_enabled
            else "Двойной клик — подключиться · правый клик — действия"
        )

    def _ensure_profile_visible(self, profile_index: int) -> None:
        if not 0 <= profile_index < len(self.profiles):
            return
        profile = self.profiles[profile_index]
        target_source = "subscriptions" if profile.subscription_id else "manual"
        if (self._profile_source != target_source or
                (target_source == "subscriptions" and self._selected_sub_id and
                 self._selected_sub_id != profile.subscription_id)):
            self._set_profile_source(target_source, profile.subscription_id or "")

    def _add_profile_row(self, profile_index: int) -> None:
        item = QListWidgetItem(self._profile_item_text(profile_index))
        item.setData(Qt.UserRole, profile_index)
        profile = self.profiles[profile_index]
        srv = str(profile.outbound.get("server") or "")
        loc = detect_location(profile.name, srv)
        latency = self.profile_latencies[profile_index] if profile_index < len(self.profile_latencies) else None
        tooltip = [profile.name]
        tooltip.append(f"Location: {loc.flag} {loc.name} ({loc.code})")
        if profile.subscription_id:
            sub = self.subscription_store.get(profile.subscription_id)
            if sub:
                tooltip.append(f"Subscription: {sub.name}")
        tooltip.append(f"Latency: {'timeout' if latency is None else f'{latency} ms'}")
        tooltip.append(f"Traffic: {self._format_bytes(self.profile_usage_bytes[profile_index])}")
        quality = self.quality.quality(profile.id)
        if quality:
            tooltip.append(f'Quality: {quality.score:.0f}/100 | Availability: {quality.reliability:.0%} '
                           f'| RTT jitter: {quality.jitter_ms if quality.jitter_ms is not None else "unknown"} ms')
        last_used = self._profile_last_used_timestamp(profile_index)
        if last_used > 0:
            tooltip.append(f"Last used: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_used))}")
        item.setToolTip("\n".join(tooltip))
        self.profile_list.addItem(item)
        self._profile_row_items[profile_index] = item

    def _select_first_selectable_row(self) -> None:
        for row in range(self.profile_list.count()):
            item = self.profile_list.item(row)
            if item is not None and item.flags() & Qt.ItemIsSelectable:
                self.profile_list.setCurrentRow(row)
                return
        self.profile_list.setCurrentRow(-1)

    def _rebuild_profile_list(self, preserve_selection: bool = True) -> None:
        selected = self._selected_profile_index() if preserve_selection else None
        ordered = self._sorted_profile_indices()
        self.profile_list.blockSignals(True)
        self._profile_row_items.clear()
        self.profile_list.clear()
        self._visible_profile_indices = ordered
        for profile_index in ordered:
            self._add_profile_row(profile_index)
        self.profile_list.blockSignals(False)
        self._update_profile_list_capabilities()

        if selected is not None:
            self._set_selected_profile_index(selected)
        else:
            self._select_first_selectable_row()

        if not ordered:
            if self._profile_source == "manual":
                message = "Нет ручных конфигов.\nНажмите «Импорт» или «Вставить»."
            elif not self.subscription_store.all():
                message = "Нет подписок. Добавьте подписку на соседней вкладке."
            else:
                message = "Нет серверов для выбранной подписки или фильтра."
            self.profiles_empty_label.setText(message)
            self.profiles_empty_label.show()
        else:
            self.profiles_empty_label.hide()

    def _refresh_profile_rows(self, index: int | None = None) -> None:
        """Incremental update: O(1) for a tick of one active server."""
        visible = list(self._profile_row_items) if index is None else [index]
        for profile_index in visible:
            item = self._profile_row_items.get(profile_index)
            if item is None or not (0 <= profile_index < len(self.profiles)):
                continue
            label = self._profile_item_text(profile_index)
            if item.text() != label:
                item.setText(label)
        if index is None:
            self._sync_quick_profile_selector()
        elif 0 <= index < self.quick_profile_combo.count() and index < len(self.profiles):
            # The quick selector lists profiles in storage order, not display order.
            label = self._profile_item_text(index)
            if self.quick_profile_combo.itemText(index) != label:
                self.quick_profile_combo.blockSignals(True)
                self.quick_profile_combo.setItemText(index, label)
                self.quick_profile_combo.blockSignals(False)
        self._update_vpn_profile_label()

    def _persist_quality_store(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_quality_persist < 60.0:
            return
        # Prune history when profiles are removed. Never serialize outbound secrets.
        valid_ids = {p.id for p in self.profiles}
        history = {key: values for key, values in self.quality.dump().items() if key in valid_ids}
        self.settings.setValue('profile_quality', json.dumps(history, ensure_ascii=True))
        self._last_quality_persist = now

    def _sync_quick_profile_selector(self) -> None:
        labels = [self._profile_item_text(idx) for idx in range(len(self.profiles))]
        current = self._selected_profile_index()
        if current is None and labels:
            current = 0

        self.quick_profile_combo.blockSignals(True)
        if self.quick_profile_combo.count() != len(labels):
            self.quick_profile_combo.clear()
            for idx, label in enumerate(labels):
                self.quick_profile_combo.addItem(label, idx)
        else:
            for idx, label in enumerate(labels):
                if self.quick_profile_combo.itemText(idx) != label:
                    self.quick_profile_combo.setItemText(idx, label)
                self.quick_profile_combo.setItemData(idx, idx)
        if current is not None and 0 <= current < self.quick_profile_combo.count():
            self.quick_profile_combo.setCurrentIndex(current)
        self.quick_profile_combo.blockSignals(False)

        self.quick_profile_frame.setVisible(len(labels) > 1)
        self.quick_profile_combo.setEnabled(len(labels) > 1)

    def _refresh_location_filter(self) -> None:
        counts: dict[str, tuple[str, str, int]] = {}
        for profile in self.profiles:
            srv = str(profile.outbound.get("server") or "")
            loc = detect_location(profile.name, srv)
            if loc.code not in counts:
                counts[loc.code] = (loc.flag, loc.name, 1)
            else:
                flag, name, c = counts[loc.code]
                counts[loc.code] = (flag, name, c + 1)

        self.profile_location_combo.blockSignals(True)
        self.profile_location_combo.clear()
        self.profile_location_combo.addItem(f"🌍 All locations ({len(self.profiles)})", "ALL")

        sorted_locs = sorted(counts.items(), key=lambda item: (-item[1][2], item[1][1]))
        target_index = 0
        for i, (code, (flag, name, count)) in enumerate(sorted_locs, start=1):
            self.profile_location_combo.addItem(f"{flag} {name} ({count})", code)
            if code == self._selected_location:
                target_index = i

        if target_index >= self.profile_location_combo.count():
            target_index = 0
            self._selected_location = "ALL"
        self.profile_location_combo.setCurrentIndex(target_index)
        self.profile_location_combo.blockSignals(False)

    def _on_location_combo_changed(self, index: int) -> None:
        if index < 0:
            return
        code = self.profile_location_combo.currentData()
        if code is not None and str(code) != self._selected_location:
            self._selected_location = str(code)
            self._rebuild_profile_list(preserve_selection=True)

    def _refresh_subs_filter(self) -> None:
        subs = self.subscription_store.all()
        if self._selected_sub_id and not any(s.id == self._selected_sub_id for s in subs):
            self._selected_sub_id = ""
        self.subs_filter_combo.blockSignals(True)
        self.subs_filter_combo.clear()
        self.subs_filter_combo.addItem("Все подписки", "")
        selected_index = 0
        for sub in subs:
            count = sum(p.subscription_id == sub.id for p in self.profiles)
            self.subs_filter_combo.addItem(f"{sub.name} ({count})", sub.id)
            if self._selected_sub_id == sub.id:
                selected_index = self.subs_filter_combo.count() - 1
        self.subs_filter_combo.setCurrentIndex(selected_index)
        self.subs_filter_combo.blockSignals(False)
        subscribed = self._profile_source == "subscriptions"
        self.subs_filter_row.setVisible(subscribed and bool(subs))
        self.manual_source_btn.setChecked(not subscribed)
        self.sub_source_btn.setChecked(subscribed)
        self.import_btn.setVisible(not subscribed)
        self.clip_btn.setVisible(not subscribed)
        self.update_subs_btn.setVisible(subscribed)
        self.update_subs_btn.setEnabled(bool(subs))
        self.manage_subs_btn.setVisible(subscribed)
        self.delete_profile_btn.setVisible(not subscribed)

    def _on_subs_filter_changed(self, index: int) -> None:
        if index < 0:
            return
        sub_id = self.subs_filter_combo.currentData()
        if sub_id is not None and str(sub_id) != self._selected_sub_id:
            self._selected_sub_id = str(sub_id)
            self._rebuild_profile_list(preserve_selection=True)

    def _refresh_profile_views(self, preserve_selection: bool = True) -> None:
        self._refresh_location_filter()
        self._refresh_subs_filter()
        self._rebuild_profile_list(preserve_selection=preserve_selection)
        self._sync_quick_profile_selector()
        self._refresh_latency_update_labels()
        self.vpn_empty_frame.setVisible(not self.profiles)
        self._update_vpn_profile_label()
        self._update_status_bar()
        self._update_tray_menu()

    def _on_profile_list_row_changed(self, row: int) -> None:
        if row < 0:
            return
        item = self.profile_list.item(row)
        if item is None:
            return
        profile_index = item.data(Qt.UserRole)
        if not isinstance(profile_index, int):
            return
        if self.quick_profile_combo.currentIndex() == profile_index:
            return
        self.quick_profile_combo.blockSignals(True)
        self.quick_profile_combo.setCurrentIndex(profile_index)
        self.quick_profile_combo.blockSignals(False)
        self._update_vpn_profile_label()

    def _on_quick_profile_changed(self, combo_index: int) -> None:
        if combo_index < 0 or combo_index >= len(self.profiles):
            return
        if self._selected_profile_index() == combo_index:
            return
        self._ensure_profile_visible(combo_index)
        self._set_selected_profile_index(combo_index)

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

        ping_action = QAction("Test ping (all profiles)", self)
        ping_action.setShortcut(QKeySequence("Ctrl+P"))
        ping_action.triggered.connect(self.refresh_latencies)
        menu.addAction(ping_action)

        diag_action = QAction('Run diagnostics', self)
        diag_action.setShortcut(QKeySequence('Ctrl+6'))
        diag_action.triggered.connect(lambda: (self._set_bottom_page(5), self.run_diagnostics()))
        menu.addAction(diag_action)

        logs_action = QAction("Open logs", self)
        logs_action.setShortcut(QKeySequence("Ctrl+5"))
        logs_action.triggered.connect(lambda: self._set_bottom_page(4))
        menu.addAction(logs_action)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        menu.addAction(quit_action)

        sub_menu = self.menuBar().addMenu("Subscriptions")

        update_subs_action = QAction("Update all subscriptions", self)
        update_subs_action.setShortcut(QKeySequence("Ctrl+U"))
        update_subs_action.triggered.connect(lambda: self.update_all_subscriptions(silent=False))
        sub_menu.addAction(update_subs_action)

        manage_subs_action = QAction("Manage subscriptions...", self)
        manage_subs_action.triggered.connect(self.show_subscriptions_dialog)
        sub_menu.addAction(manage_subs_action)

        add_sub_action = QAction("Add subscription...", self)
        add_sub_action.triggered.connect(self.add_subscription_dialog)
        sub_menu.addAction(add_sub_action)

    def _connect_signals(self) -> None:
        self.vpn.status_changed.connect(self._on_vpn_status_changed)
        self.vpn.profile_starting.connect(self._on_vpn_profile_starting)
        self.vpn.connection_lost.connect(self._on_connection_lost)
        self.diagnostics_ready.connect(self._on_diagnostics_ready)
        self.vpn.log_line.connect(self._append_log)
        self.vpn.error.connect(self._show_error)
        self.vpn.singbox_availability_changed.connect(self._on_singbox_availability_changed)
        self.vpn.install_state_changed.connect(self._on_install_state_changed)
        self.latencies_ready.connect(self._on_latencies_ready)
        self.resume_probe_finished.connect(self._on_resume_probe_finished)
        self.profile_list.currentRowChanged.connect(self._on_profile_list_row_changed)
        self.profile_list.customContextMenuRequested.connect(self._show_profile_context_menu)
        self.profile_list.itemDoubleClicked.connect(lambda _item: self._connect_selected_profile())
        self.profile_list.files_dropped.connect(self._import_dropped_files)
        self.profile_list.links_dropped.connect(self._import_dropped_links)
        self.profile_list.items_reordered.connect(self._on_profile_items_reordered)
        self.happ_import_finished.connect(self._on_happ_import_finished)
        self.worker_log.connect(self._append_log)
        self.subscription_update_finished.connect(self._on_subscription_update_finished)
        self.quick_profile_combo.currentIndexChanged.connect(self._on_quick_profile_changed)
        self.profile_search_edit.textChanged.connect(self._on_profile_filter_changed)
        self.profile_sort_combo.currentIndexChanged.connect(self._on_profile_filter_changed)
        self.profile_location_combo.currentIndexChanged.connect(self._on_location_combo_changed)
        self.subs_filter_combo.currentIndexChanged.connect(self._on_subs_filter_changed)
        self.manual_source_btn.clicked.connect(lambda: self._set_profile_source("manual"))
        self.sub_source_btn.clicked.connect(lambda: self._set_profile_source("subscriptions"))
        self.subscriptions_panel.update_single_signal.connect(self.update_subscription)
        self.subscriptions_panel.update_all_signal.connect(self.update_all_subscriptions)
        self.subscriptions_panel.add_subscription_signal.connect(self._add_subscription_from_dialog)
        self.subscriptions_panel.edit_subscription_link_signal.connect(self.change_subscription_link)
        self.subscriptions_panel.delete_subscription_signal.connect(self.delete_subscription)
        self.subscriptions_panel.nodes_requested.connect(self._show_subscription_nodes)
        self.copy_logs_btn.clicked.connect(self.copy_logs)
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        self.open_log_file_btn.clicked.connect(self.open_log_file)
        self.auto_switch_checkbox.toggled.connect(lambda checked: self.settings.setValue("auto_switch", checked))
        self.auto_update_subs_checkbox.toggled.connect(
            lambda checked: self.settings.setValue("auto_update_subs", checked)
        )
        self.auto_reconnect_checkbox.toggled.connect(
            lambda value: self.settings.setValue('auto_reconnect', value))
        self.sub_update_hours_spin.valueChanged.connect(
            lambda value: self.settings.setValue('sub_update_hours', value))
        self.advanced_checkbox.toggled.connect(self._apply_advanced_mode)
        self.auto_redirect_checkbox.toggled.connect(self._on_auto_redirect_changed)
        self.timeout_spin.valueChanged.connect(lambda value: self.settings.setValue("timeout_ms", value))
        self.route_mode_combo.currentIndexChanged.connect(self._on_route_mode_changed)
        self.dns_mode_combo.currentIndexChanged.connect(self._on_dns_mode_changed)
        self.app_mode_combo.currentIndexChanged.connect(self._on_app_mode_changed)
        self.application_list.itemChanged.connect(self._on_application_item_changed)
        self.custom_dns_edit.textChanged.connect(self._on_custom_dns_changed)
        self.ignore_ru_domains_checkbox.toggled.connect(self._on_ignore_ru_domains_changed)
        self.include_subdomains_checkbox.toggled.connect(self._on_include_subdomains_changed)
        self.domains_edit.textChanged.connect(self._on_domains_text_changed)

    def _restore_settings(self) -> None:
        auto_switch = self.settings.value("auto_switch", False, type=bool)
        auto_update_subs = self.settings.value("auto_update_subs", True, type=bool)
        auto_reconnect = self.settings.value('auto_reconnect', True, type=bool)
        advanced = self.settings.value('ui/advanced', False, type=bool)
        auto_redirect = self.settings.value('route_auto_redirect', False, type=bool)
        update_hours = self.settings.value('sub_update_hours', 12, type=int)
        timeout_ms = self.settings.value("timeout_ms", 1200, type=int)
        route_mode = self.settings.value("route_mode", "all", type=str) or "all"
        route_dns_mode = self.settings.value("route_dns_mode", "", type=str) or ""
        if not route_dns_mode:
            legacy_proxy_dns = self.settings.value("route_proxy_dns", True, type=bool)
            route_dns_mode = "proxy" if legacy_proxy_dns else "direct"
        route_custom_dns = self.settings.value("route_custom_dns", "", type=str) or ""
        app_mode = self.settings.value("route_app_mode", "disabled", type=str) or "disabled"
        include_subdomains = self.settings.value("route_include_subdomains", True, type=bool)
        ignore_ru_domains = self.settings.value("route_ignore_ru_domains", False, type=bool)
        route_domains_text = self.settings.value("route_domains_text", "", type=str) or ""
        usage_raw = self.settings.value("profile_usage_bytes", "{}", type=str) or "{}"
        last_used_raw = self.settings.value("profile_last_used", "{}", type=str) or "{}"
        fav_raw = self.settings.value('ui/favorites', '[]', type=str) or '[]'
        quality_raw = self.settings.value('profile_quality', '{}', type=str) or '{}'
        try:
            favorites = json.loads(fav_raw)
            self.favorite_profile_ids = set(str(x) for x in favorites) if isinstance(favorites, list) else set()
        except ValueError:
            self.favorite_profile_ids = set()
        try:
            self.quality = QualityTracker(json.loads(quality_raw))
        except (TypeError, ValueError):
            self.quality = QualityTracker()
        try:
            parsed_usage = json.loads(usage_raw)
            if isinstance(parsed_usage, dict):
                self._usage_store = {str(k): int(v) for k, v in parsed_usage.items()}
            else:
                self._usage_store = {}
        except (ValueError, TypeError):
            self._usage_store = {}
        try:
            parsed_last_used = json.loads(last_used_raw)
            if isinstance(parsed_last_used, dict):
                self._last_used_store = {str(k): float(v) for k, v in parsed_last_used.items()}
            else:
                self._last_used_store = {}
        except (ValueError, TypeError):
            self._last_used_store = {}

        source = self.settings.value("ui/config_source", "manual", type=str)
        self._profile_source = source if source in {"manual", "subscriptions"} else "manual"
        self.auto_switch_checkbox.setChecked(auto_switch)
        self.auto_update_subs_checkbox.setChecked(auto_update_subs)
        self.auto_reconnect_checkbox.setChecked(auto_reconnect)
        self.sub_update_hours_spin.setValue(max(1, min(update_hours, 168)))
        self.auto_redirect_checkbox.setChecked(auto_redirect)
        self.advanced_checkbox.setChecked(advanced)
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
        app_mode_index = self.app_mode_combo.findData(app_mode)
        if app_mode_index < 0 or (app_mode != 'disabled' and not self._selected_application_rules()):
            app_mode_index = 0
        self.app_mode_combo.setCurrentIndex(app_mode_index)
        self.include_subdomains_checkbox.setChecked(include_subdomains)
        self.ignore_ru_domains_checkbox.setChecked(ignore_ru_domains)
        self.domains_edit.setPlainText(route_domains_text)
        self._update_routing_controls()
        self._update_dns_controls()
        self._update_application_controls()
        self._apply_advanced_mode()

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
            xray = item.get("xray")
            loaded.append(
                Profile(
                    name=name or f"Profile {idx}",
                    outbound=outbound,
                    subscription_id=item.get("subscription_id"),
                    xray=xray if isinstance(xray, dict) else None,
                    **({'id': item['id']} if isinstance(item.get('id'), str)
                        and re.fullmatch(r'[0-9a-fA-F]{32}', item['id']) else {}),
                )
            )

        if loaded:
            migrated = self._migrate_profile_metadata(loaded)
            self._apply_loaded_profiles(loaded, persist=False)
            if migrated or any(not isinstance(x.get('id'), str) for x in raw_profiles if isinstance(x, dict)):
                self._save_profiles()
            self._append_log(f"Loaded {len(loaded)} saved profile(s) from {path}")

    def _write_profiles_atomically(self, payload: dict) -> None:
        path = profiles_path()
        backup_path = path.with_suffix(path.suffix + '.bak')
        if path.exists():
            try:
                shutil.copy2(path, backup_path)
                ensure_user_owned(backup_path)
                backup_path.chmod(0o600)
            except OSError:
                pass
        atomic_private_json(path, payload)
        ensure_user_owned(path)

    def _save_profiles(self) -> None:
        payload = {
            "profiles": [
                {
                    "name": profile.name,
                    "id": profile.id,
                    "outbound": profile.outbound,
                    "subscription_id": profile.subscription_id,
                    **({"xray": profile.xray} if profile.xray else {}),
                }
                for profile in self.profiles
            ]
        }
        try:
            self._write_profiles_atomically(payload)
        except OSError as exc:
            self._append_log(f"Failed to save profiles: {exc}")

    def _apply_advanced_mode(self, _checked: bool | None = None) -> None:
        advanced = self.advanced_checkbox.isChecked()
        self.settings.setValue('ui/advanced', advanced)
        for widget in self._advanced_widgets:
            widget.setVisible(advanced)
        if advanced:
            self._update_routing_controls()
            self._update_dns_controls()

    def _apply_route_preset(self) -> None:
        key = str(self.preset_combo.currentData() or 'all')
        if self.domains_edit.toPlainText().strip() or self.route_mode_combo.currentData() != 'all':
            answer = QMessageBox.question(self, 'Apply routing preset',
                        'Replace the current domain/IP routing rules with this preset? '
                        'Application rules and DNS settings will be preserved.',
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        mode, ignore_ru, domains = preset_values(key)
        self.route_mode_combo.setCurrentIndex(self.route_mode_combo.findData(mode))
        self.ignore_ru_domains_checkbox.setChecked(ignore_ru)
        self.domains_edit.setPlainText(domains)
        self._append_log(f'Applied routing preset: {key}')

    def _on_auto_redirect_changed(self, checked: bool) -> None:
        if checked and not shutil.which('nft'):
            self.auto_redirect_checkbox.blockSignals(True)
            self.auto_redirect_checkbox.setChecked(False)
            self.auto_redirect_checkbox.blockSignals(False)
            self._append_log('auto_redirect requires the nftables utility; setting not applied')
            checked = False
        self.settings.setValue('route_auto_redirect', checked)
        self._schedule_live_routing_apply()

    def _on_route_mode_changed(self, _index: int = -1) -> None:
        self.settings.setValue("route_mode", self.route_mode_combo.currentData())
        self._update_routing_controls()
        self._apply_advanced_mode()
        self._schedule_live_routing_apply()

    def _on_dns_mode_changed(self, _index: int = -1) -> None:
        self.settings.setValue("route_dns_mode", self.dns_mode_combo.currentData())
        self._update_dns_controls()
        self._apply_advanced_mode()
        self._schedule_live_routing_apply()

    def _on_app_mode_changed(self, _index: int = -1) -> None:
        self.settings.setValue("route_app_mode", self.app_mode_combo.currentData())
        self._update_application_controls()
        self._schedule_live_routing_apply()

    def _on_custom_dns_changed(self, value: str) -> None:
        self.settings.setValue("route_custom_dns", value)
        self._schedule_live_routing_apply()

    def _on_ignore_ru_domains_changed(self, checked: bool) -> None:
        self.settings.setValue("route_ignore_ru_domains", checked)
        self._schedule_live_routing_apply()

    def _on_include_subdomains_changed(self, checked: bool) -> None:
        self.settings.setValue("route_include_subdomains", checked)
        self._schedule_live_routing_apply()

    def _on_domains_text_changed(self) -> None:
        self.settings.setValue("route_domains_text", self.domains_edit.toPlainText())
        self._schedule_live_routing_apply()

    def _schedule_live_routing_apply(self) -> None:
        """Debounce route-setting changes and apply them to the active tunnel.

        sing-box does not reload route/DNS rules from its JSON file while it is
        running. Reconnecting the current profile is the safe way to apply a
        complete, validated config without restarting the GUI.
        """
        if self.vpn.status not in {"connected", "connecting"}:
            return
        self._live_apply_timer.start()

    def _apply_routing_changes_live(self) -> None:
        if self.vpn.status not in {"connected", "connecting"}:
            return
        routing = self._routing_options()
        if routing.app_mode != 'disabled' and not (routing.app_process_names or routing.app_process_paths):
            self._append_log('Choose at least one app before applying application routing.')
            return
        if routing.dns_mode == "custom" and routing.custom_dns.strip():
            try:
                # Reject malformed in-progress edits before stopping a healthy
                # tunnel. The live DNS probe still runs in VpnManager later.
                self.vpn._parse_custom_dns_target(routing.custom_dns)
            except ValueError as exc:
                self._append_log(f"Routing change not applied yet: {exc}")
                return
        index = self.connected_index
        if index is None or not (0 <= index < len(self.profiles)):
            index = self._selected_profile_index()
        if index is None or not (0 <= index < len(self.profiles)):
            self._append_log("Routing changed, but there is no active profile to reconnect.")
            return
        self._append_log("Routing/DNS/application settings changed; applying to the active tunnel...")
        self._connect_profile(index)

    def _read_saved_application_rules(self) -> list[dict[str, str]]:
        raw = self.settings.value("route_applications", "[]", type=str) or "[]"
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return []
        if not isinstance(parsed, list):
            return []
        result: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in parsed:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            path = str(item.get("path") or "").strip()
            if not name and not path:
                continue
            key = (name, path)
            if key in seen:
                continue
            seen.add(key)
            result.append({"name": name, "path": path})
        return result

    def _discover_running_applications(self) -> list[dict[str, str]]:
        """Compatibility shim for running process discovery; no Qt required."""
        return [{'name': app.process_name, 'path': app.path} for app in running_applications()]

    def _rescan_application_catalog(self) -> None:
        self._installed_apps = None
        self._refresh_application_list()

    def _icon_for_application(self, app: DesktopApp) -> QIcon:
        key = app.icon or app.path
        cached = self._desktop_icons.get(key)
        if cached is not None:
            return cached
        icon = QIcon()
        if app.icon:
            if os.path.isabs(app.icon):
                icon = QIcon(app.icon)
            else:
                icon = QIcon.fromTheme(app.icon)
        if icon.isNull() and app.path:
            # QFileIconProvider respects desktop environment mappings; on Linux
            # Qt's icon theme resolves names from freedesktop .desktop entries.
            icon = QFileIconProvider().icon(QFileInfo(app.path))
        if icon.isNull():
            icon = QIcon.fromTheme('application-x-executable')
        if icon.isNull():
            icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self._desktop_icons[key] = icon
        return icon

    def _refresh_application_list(self) -> None:
        saved = self._read_saved_application_rules()
        if self._installed_apps is None:
            self._installed_apps = installed_applications()
        running = running_applications()
        merged = merge_applications(self._installed_apps, running, saved)
        saved_keys = {identity(item['name'], item['path']) for item in saved}

        # Show the applications people recognize, not 200 mostly-system /proc
        # entries. 'Запущенные' still exposes raw processes when needed.
        merged.sort(key=lambda app: (identity(app.process_name, app.path) not in saved_keys,
                                     app.source == 'running', app.name.casefold()))
        self.application_list.blockSignals(True)
        self.application_list.clear()
        for app in merged:
            key = identity(app.process_name, app.path)
            label = app.name
            if app.running and app.source != 'running':
                label += '  ·  запущено'
            row = QListWidgetItem(self._icon_for_application(app), label)
            row.setSizeHint(QSize(0, 48))
            row.setFlags(row.flags() | Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
            row.setCheckState(Qt.Checked if key in saved_keys else Qt.Unchecked)
            row.setData(Qt.UserRole, app.rule())
            row.setData(Qt.UserRole + 1, {
                'source': app.source, 'running': app.running,
                'display': app.name, 'path': app.path,
            })
            row.setToolTip(f'{app.name}\n{app.path or app.process_name}\n'
                           + ('Запущено' if app.running else 'Не запущено'))
            self.application_list.addItem(row)
        self.application_list.blockSignals(False)
        self._filter_application_list()
        self._update_application_selection_label()

    def _filter_application_list(self, _text: str = '') -> None:
        query = self.app_search_edit.text().strip().casefold()
        source = self.app_source_combo.currentData() or 'all'
        for index in range(self.application_list.count()):
            item = self.application_list.item(index)
            data = item.data(Qt.UserRole) or {}
            meta = item.data(Qt.UserRole + 1) or {}
            selected = item.checkState() == Qt.Checked
            name = str(meta.get('display') or data.get('name') or '')
            path = str(data.get('path') or '')
            matches = not query or query in f'{name} {path} {data.get("name", "")}'.casefold()
            if source == 'selected':
                visible = selected
            elif source == 'running':
                visible = bool(meta.get('running')) or selected
            else:
                visible = meta.get('source') != 'running' or selected
            item.setHidden(not (matches and visible))

    def _add_application_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Выберите исполняемый файл', '/usr/bin')
        if not path:
            return
        executable = Path(path)
        if not executable.is_file() or not os.access(path, os.X_OK):
            self._show_error('Выбранный файл не является исполняемым.')
            return
        try:
            executable = executable.resolve()
        except OSError:
            pass
        saved = self._read_saved_application_rules()
        item = {'name': '', 'path': str(executable)}
        if not any(identity(x.get('name', ''), x.get('path', '')) == identity('', item['path'])
                   for x in saved):
            saved.append(item)
            self.settings.setValue('route_applications', json.dumps(saved, ensure_ascii=False))
        self._refresh_application_list()
        if self.app_mode_combo.currentData() == 'disabled':
            self._select_app_mode('proxy_selected')
        self._schedule_live_routing_apply()

    def _selected_application_rules(self) -> list[dict[str, str]]:
        selected: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for index in range(self.application_list.count()):
            item = self.application_list.item(index)
            if item.checkState() != Qt.Checked:
                continue
            data = item.data(Qt.UserRole)
            if isinstance(data, dict):
                name, path = str(data.get('name') or ''), str(data.get('path') or '')
                key = identity(name, path)
                if key not in seen:
                    seen.add(key)
                    selected.append({'name': name if not path else '', 'path': path})
        return selected

    def _save_selected_application_rules(self) -> None:
        self.settings.setValue('route_applications', json.dumps(self._selected_application_rules(), ensure_ascii=False))
        self._update_application_selection_label()
        self._filter_application_list()

    def _select_app_mode(self, mode: str) -> None:
        if mode != 'disabled' and not self._selected_application_rules():
            self.app_search_edit.setFocus()
            self.app_mode_explanation.setText('Сначала отметьте нужные программы в списке ниже.')
            return
        index = self.app_mode_combo.findData(mode)
        if index >= 0:
            self.app_mode_combo.setCurrentIndex(index)

    def _on_application_item_changed(self, item: QListWidgetItem) -> None:
        self._save_selected_application_rules()
        count = len(self._selected_application_rules())
        if item.checkState() == Qt.Checked and self.app_mode_combo.currentData() == 'disabled':
            self._select_app_mode('proxy_selected')
        elif count == 0 and self.app_mode_combo.currentData() != 'disabled':
            self._select_app_mode('disabled')
        self._update_application_controls()
        self._schedule_live_routing_apply()

    def _update_application_selection_label(self) -> None:
        count = len(self._selected_application_rules()) if hasattr(self, 'application_list') else 0
        self.app_selection_label.setText(f'Выбрано: {count}' if count else 'Не выбрано')
        self._update_app_quick_action()

    def _update_app_quick_action(self) -> None:
        if not hasattr(self, 'app_quick_btn'):
            return
        count = len(self._selected_application_rules()) if hasattr(self, 'application_list') else 0
        mode = self.app_mode_combo.currentData()
        if mode == 'proxy_selected':
            label = f'Только выбранные приложения: {count}'
        elif mode == 'direct_selected':
            label = f'VPN для всех, кроме {count} приложений'
        else:
            label = 'Маршрутизация приложений  ·  Настроить'
        self.app_quick_btn.setText(label)

    def _update_application_controls(self) -> None:
        mode = self.app_mode_combo.currentData()
        count = len(self._selected_application_rules())
        for key, button in self.app_mode_buttons.items():
            button.setChecked(key == mode)
            button.setEnabled(key == 'disabled' or count > 0)
        if mode == 'proxy_selected':
            explanation = (f'Через VPN идут только отмеченные программы ({count}). '
                           'Весь остальной трафик — напрямую. DNS системы остаётся общим.')
        elif mode == 'direct_selected':
            explanation = (f'Отмеченные программы ({count}) обходят VPN. '
                           'Остальные используют VPN. DNS системы остаётся общим.')
        else:
            explanation = ('Обычный режим: используются правила маршрутизации из настроек. '
                           'Отметьте программу, чтобы включить режим «Только выбранные».')
        if mode != 'disabled' and count == 0:
            explanation = 'Выберите хотя бы одно приложение. Пока ничего не выбрано, изменение VPN не применяется.'
        self.app_mode_explanation.setText(explanation)
        self.application_list.setEnabled(True)
        self._update_app_quick_action()

    def _update_routing_controls(self) -> None:
        needs_domains = self.route_mode_combo.currentData() in {"only_selected", "all_except_selected"}
        self.routing_domains_frame.setVisible(needs_domains)
        self.routing_mode_hint.setVisible(needs_domains)
        if needs_domains:
            self.routing_mode_hint.setText("One domain or IP/CIDR per line.")
        else:
            self.routing_mode_hint.setText("")

    def _update_dns_controls(self) -> None:
        needs_custom_dns = self.dns_mode_combo.currentData() == "custom"
        self.custom_dns_frame.setVisible(needs_custom_dns)
        if needs_custom_dns:
            self.custom_dns_hint.setText("IP or host; udp:// and tcp:// are supported.")
        else:
            self.custom_dns_hint.setText("Select Custom DNS to enter an address.")

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

    def _warn_if_not_running_as_sudo(self) -> None:
        if os.name != "posix":
            return
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            return
        if is_root:
            return
        if self.vpn.singbox_has_net_admin():
            self._append_log("sing-box has CAP_NET_ADMIN; running without sudo.")
            return

        message = (
            "Run the application with sudo, otherwise VPN connection and TUN setup may not work correctly."
        )
        QMessageBox.warning(self, "Run with sudo", message)
        self._append_log(f"WARNING: {message}")

    def _load_profiles_from_paths(self, paths: list[Path], source_label: str) -> None:
        imported_total = 0
        for path in paths:
            try:
                loaded = load_profiles(path)
            except (OSError, ValueError, ConfigError) as exc:
                self._append_log(f"Failed to import {path}: {exc}")
                continue
            self._apply_loaded_profiles(loaded)
            imported_total += len(loaded)
            self._append_log(f"Imported {len(loaded)} profile(s) from {source_label}: {path}")
        if imported_total:
            self._notify_user("Profiles imported", f"Imported {imported_total} profile(s)")
        else:
            self._show_error("No valid profiles were imported")

    def import_config(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open config",
            str(import_configs_dir()),
            "Config files (*.json *.txt *.conf);;All files (*)",
        )
        if not path_str:
            return
        self._load_profiles_from_paths([Path(path_str)], "file")

    def _import_dropped_files(self, paths: list[str]) -> None:
        candidates = [Path(path) for path in paths if Path(path).is_file()]
        if not candidates:
            return
        self._load_profiles_from_paths(candidates, "drag-and-drop")

    def _import_dropped_links(self, links: list[str]) -> None:
        for link in links:
            if is_happ_link(link) or is_likely_subscription_url(link):
                self._start_happ_import(link, "drag-and-drop")

    def _start_happ_import(self, link: str, source_label: str, custom_name: str = "") -> None:
        link = link.strip()
        if not link:
            return
        # Extract clean URL if surrounding text or non-ASCII characters got attached
        match = re.search(r"(happ://[^\s\"<>]+|https?://[A-Za-z0-9_.~:/?#\[\]@!$&()*+,;=-]+)", link)
        if match:
            link = match.group(1).rstrip("\"';,.<>")

        self.subscriptions_panel.set_feedback("Добавление подписки…")
        self._append_log(f"Importing subscription / Happ link from {source_label}")
        worker = threading.Thread(
            target=self._happ_import_worker,
            args=(link, source_label, custom_name),
            daemon=True,
        )
        worker.start()

    def _happ_import_worker(self, link: str, source_label: str, custom_name: str = "") -> None:
        try:
            profiles, target_url, headers_info = fetch_subscription_profiles(link)
            self._prefetch_rule_sets(profiles)
            sub_id = generate_subscription_id(target_url or link)
            sub_name = custom_name.strip() if custom_name else derive_subscription_name(target_url or link, headers_info)
            for p in profiles:
                p.subscription_id = sub_id
            meta = {
                "sub_id": sub_id,
                "name": sub_name,
                "custom_name": bool(custom_name.strip()),
                "url": target_url,
                "original_link": link,
                "headers_info": headers_info,
            }
            self.happ_import_finished.emit(source_label, (profiles, meta), "")
        except Exception as exc:
            self.happ_import_finished.emit(source_label, [], str(exc))

    def _prefetch_rule_sets(self, profiles: list[Profile]) -> None:
        """Runs in worker threads so that connecting a Happ-config profile never waits on downloads."""
        names: set[tuple[str, str]] = set()
        for profile in profiles:
            if profile.xray:
                names |= required_rule_sets(profile.xray)
        if names:
            ensure_rule_sets(names)

    def _on_happ_import_finished(self, source_label: str, loaded: object, error: str) -> None:
        if error:
            safe_error = redact(error)
            self.subscriptions_panel.set_feedback(f"Не удалось добавить: {safe_error}", error=True)
            self._show_error(f"Failed to import from {source_label}: {safe_error}")
            return

        profiles: list[Profile] = []
        meta: dict[str, Any] = {}
        if isinstance(loaded, tuple) and len(loaded) == 2:
            profiles = [p for p in loaded[0] if isinstance(p, Profile)]
            meta = dict(loaded[1]) if isinstance(loaded[1], dict) else {}
        elif isinstance(loaded, list):
            profiles = [p for p in loaded if isinstance(p, Profile)]

        if not profiles:
            self._show_error("Link did not contain any usable profiles")
            return

        sub_id = meta.get("sub_id")
        if sub_id:
            sub = Subscription(
                id=sub_id,
                name=meta.get("name", "Subscription"),
                url=meta.get("url", ""),
                original_link=meta.get("original_link", ""),
                updated_at=time.time(),
                profile_count=len(profiles),
                user_info=meta.get("headers_info", {}).get("user_info", {}) if isinstance(meta.get("headers_info"), dict) else {},
            )
            existing = self.subscription_store.get(sub_id)
            if existing:
                sub.auto_update = existing.auto_update
                if not meta.get("custom_name"):
                    sub.name = existing.name
                if not sub.user_info:
                    sub.user_info = existing.user_info
            self.subscription_store.put(sub)
            self._notify_quota(sub)
            self._apply_updated_subscription_profiles(sub_id, profiles)
        else:
            self._apply_loaded_profiles(profiles)

        self.subscriptions_panel.set_feedback(f"Добавлено серверов: {len(profiles)}")
        self.subscriptions_panel.refresh_list()
        self._append_log(f"Imported {len(profiles)} profile(s) from {source_label}")
        self._notify_user("Profiles imported", f"Imported {len(profiles)} profile(s)")

    def _auto_update_subscriptions_startup(self) -> None:
        """Run only due, individually opted-in subscriptions; bounded workers."""
        if not self.auto_update_subs_checkbox.isChecked():
            return
        now = time.time()
        interval = self.sub_update_hours_spin.value()
        for sub in self.subscription_store.all():
            if subscription_due(sub, now, interval):
                self._queue_subscription_update(sub, silent=True)

    def show_subscriptions_dialog(self) -> None:
        """Backward-compatible entry point; subscriptions now live in the main window."""
        self._set_bottom_page(6)

    def add_subscription_dialog(self) -> None:
        self.show_subscriptions_dialog()
        self.subscriptions_panel.open_add_dialog()

    def _add_subscription_from_dialog(self, url: str, name: str) -> None:
        self._start_happ_import(url, "dialog", custom_name=name)

    def change_subscription_link(self, sub_id: str, link: str) -> None:
        sub = self.subscription_store.get(sub_id)
        if not sub:
            return
        if sub.id in self._subs_inflight:
            self.subscriptions_panel.set_update_state(sub_id, "Дождитесь текущего обновления", busy=True)
            return
        # Test the new link before saving it. A bad link must not destroy a
        # valid subscription or its nodes.
        self._pending_subscription_links[sub_id] = link.strip()
        self._queue_subscription_update(sub, silent=False, force=True, source_url=link.strip())

    def update_subscription(self, sub_id: str) -> None:
        sub = self.subscription_store.get(sub_id)
        if not sub:
            self._show_error('Subscription not found')
            return
        self._queue_subscription_update(sub, silent=False, force=True)

    def update_all_subscriptions(self, silent: bool = False) -> None:
        subs = self.subscription_store.all()
        if not subs:
            if not silent:
                self._notify_user('Subscriptions', 'No subscriptions configured')
            return
        if silent:
            self._auto_update_subscriptions_startup()
        else:
            self._append_log(f'Updating {len(subs)} subscriptions (up to two at a time)...')
            for sub in subs:
                self._queue_subscription_update(sub, silent=False, force=True)

    def _queue_subscription_update(self, sub: Subscription, *, silent: bool,
                                   force: bool = False, source_url: str | None = None) -> None:
        if sub.id in self._subs_inflight:
            return
        if not force and time.time() < self._subscription_retry_at.get(sub.id, 0):
            return
        self._subs_inflight.add(sub.id)
        self.subscriptions_panel.set_update_state(sub.id, "Обновление…", busy=True)
        if silent:
            self._subs_silent.add(sub.id)
        self._subscription_pool.submit(self._subscription_update_worker,
                                       sub.id, source_url or sub.original_link or sub.url, sub.name)

    def _notify_quota(self, sub: Subscription) -> None:
        stats = sub.traffic_stats()
        if not stats.has_data:
            return
        now = time.time()
        warnings = []
        if stats.expire and 0 < stats.expire - now <= 3 * 24 * 3600:
            warnings.append(f'expires on {stats.expire_str}')
        if stats.over_quota:
            warnings.append('quota exceeded')
        elif not stats.unlimited and stats.remaining is not None and stats.percent >= 90:
            warnings.append(f'{format_bytes(stats.remaining)} remaining')
        if not warnings:
            return
        last = float(self.settings.value(f'quota_alert/{sub.id}', 0.0) or 0.0)
        if now - last < 24 * 3600:
            return
        self.settings.setValue(f'quota_alert/{sub.id}', now)
        self._notify_user(f'Subscription: {sub.name}', ', '.join(warnings))
        self._append_log(f'Subscription alert for {sub.name}: {", ".join(warnings)}')

    def _subscription_update_worker(self, sub_id: str, url: str, name: str) -> None:
        try:
            profiles, target_url, headers_info = fetch_subscription_profiles(url)
            self._prefetch_rule_sets(profiles)
            self.subscription_update_finished.emit(sub_id, profiles, headers_info, "")
        except Exception as exc:
            self.subscription_update_finished.emit(sub_id, [], {}, str(exc))

    def _on_subscription_update_finished(self, sub_id: str, profiles: object, headers_info: object, error: str) -> None:
        self._subs_inflight.discard(sub_id)
        silent = sub_id in self._subs_silent
        self._subs_silent.discard(sub_id)
        sub = self.subscription_store.get(sub_id)
        if sub is None:
            # An in-flight update must never resurrect a deleted subscription.
            return
        sub_name = sub.name
        if error:
            self._pending_subscription_links.pop(sub_id, None)
            failures = self._subscription_failures.get(sub_id, 0) + 1
            self._subscription_failures[sub_id] = failures
            self._subscription_retry_at[sub_id] = time.time() + min(6 * 3600, 600 * 2 ** (failures - 1))
            self._append_log(f"Failed to update subscription '{sub_name}': {redact(error)}")
            self.subscriptions_panel.set_update_state(sub_id, f"Ошибка: {redact(error)}", error=True)
            if not silent and self.content_stack.currentIndex() != 6:
                self._show_error(f"Subscription update failed ({sub_name}): {redact(error)}")
            return
        self._subscription_failures.pop(sub_id, None)
        self._subscription_retry_at.pop(sub_id, None)
        if not isinstance(profiles, list) or not profiles:
            self._pending_subscription_links.pop(sub_id, None)
            self._append_log(f"Subscription '{sub_name}' returned no profiles")
            # Still persist quota info from the response headers when present.
            if sub and isinstance(headers_info, dict) and headers_info.get("user_info"):
                sub.user_info = headers_info["user_info"]
                sub.updated_at = time.time()
                self.subscription_store.put(sub)
            self.subscriptions_panel.set_update_state(sub_id, "Серверы не найдены", error=True)
            if not silent and self.content_stack.currentIndex() != 6:
                self._show_error(f"Subscription '{sub_name}' returned no profiles")
            return

        loaded_profiles = [p for p in profiles if isinstance(p, Profile)]
        # Persist a newly edited URL only if the fetch returned usable nodes.
        edited_link = self._pending_subscription_links.pop(sub_id, None)
        if edited_link:
            sub.original_link = edited_link
            sub.url = edited_link
        if sub:
            sub.updated_at = time.time()
            sub.profile_count = len(loaded_profiles)
            # Missing/unparseable userinfo must not wipe the previous quota.
            if isinstance(headers_info, dict) and headers_info.get("user_info"):
                sub.user_info = headers_info["user_info"]
            self.subscription_store.put(sub)
            self._notify_quota(sub)

        self._apply_updated_subscription_profiles(sub_id, loaded_profiles)
        self._append_log(f"Updated subscription '{sub_name}': {len(loaded_profiles)} profile(s)")
        self.subscriptions_panel.set_update_state(sub_id, f"Готово · {len(loaded_profiles)} серверов")
        self.subscriptions_panel.refresh_list()

    def delete_subscription(self, sub_id: str) -> None:
        sub = self.subscription_store.get(sub_id)
        if not sub:
            return
        indices_to_remove = [i for i, p in enumerate(self.profiles) if p.subscription_id == sub_id]
        if self.connected_index in indices_to_remove:
            self._stop_connection()
            self.connected_index = None

        self.profiles = [p for i, p in enumerate(self.profiles) if i not in indices_to_remove]
        self.profile_latencies = [l for i, l in enumerate(self.profile_latencies) if i not in indices_to_remove]
        self.profile_usage_bytes = [u for i, u in enumerate(self.profile_usage_bytes) if i not in indices_to_remove]

        self.subscription_store.remove(sub_id)
        self._pending_subscription_links.pop(sub_id, None)
        self._subs_inflight.discard(sub_id)
        self.subscriptions_panel.refresh_list()
        self._pending_latency_indices = set(range(len(self.profiles)))
        self._save_profiles()
        self._refresh_location_filter()
        self._refresh_profile_views()
        self._notify_user("Subscription deleted", f'Removed subscription "{sub.name}"')
        self._append_log(f'Deleted subscription "{sub.name}" and {len(indices_to_remove)} profile(s)')

    def _apply_updated_subscription_profiles(self, sub_id: str, new_profiles: list[Profile]) -> None:
        if not new_profiles:
            return
        old_nodes = [p for p in self.profiles if p.subscription_id == sub_id]
        by_signature: dict[str, list[Profile]] = {}
        by_endpoint: dict[tuple[str, str, str, str], list[Profile]] = {}

        def endpoint(profile: Profile) -> tuple[str, str, str, str]:
            ob = profile.outbound
            return (str(ob.get('type', '')), str(ob.get('server', '')),
                    str(ob.get('server_port', '')), profile.name)

        for old in old_nodes:
            by_signature.setdefault(self._profile_signature(old), []).append(old)
            by_endpoint.setdefault(endpoint(old), []).append(old)
        used_ids: set[str] = set()
        for new in new_profiles:
            new.subscription_id = sub_id
            similar = by_signature.get(self._profile_signature(new), [])
            if not similar:
                similar = by_endpoint.get(endpoint(new), [])
            match = next((old for old in similar if old.id not in used_ids), None)
            if match is not None:
                new.id = match.id
                used_ids.add(match.id)

        connected = (self.profiles[self.connected_index]
                     if self.connected_index is not None and 0 <= self.connected_index < len(self.profiles)
                     else None)
        new_items: list[Profile] = []
        replaced = False
        for profile in self.profiles:
            if profile.subscription_id == sub_id:
                if not replaced:
                    new_items.extend(new_profiles)
                    replaced = True
            else:
                new_items.append(profile)
        if not replaced:
            new_items.extend(new_profiles)
        # The running TUN may still use a node removed by the subscription.
        # Retain a detached entry so the UI/stats remain consistent until stopped.
        if connected is not None and connected.subscription_id == sub_id and not any(
            p.id == connected.id for p in new_items
        ) and self.vpn.status in {'connected', 'connecting'}:
            # Keep the source association: a temporary provider node must not
            # suddenly appear in the user's manually imported configurations.
            connected.name += ' (active, removed from subscription)'
            new_items.append(connected)
            self._append_log('Active server disappeared from subscription; keeping current tunnel until disconnect.')

        latency_by_id = {p.id: self.profile_latencies[i] if i < len(self.profile_latencies) else None
                         for i, p in enumerate(self.profiles)}
        current_usage = {p.id: self.profile_usage_bytes[i] if i < len(self.profile_usage_bytes) else 0
                         for i, p in enumerate(self.profiles)}
        self.profiles = new_items
        self.profile_latencies = [latency_by_id.get(p.id) for p in new_items]
        self.profile_usage_bytes = [current_usage.get(p.id, self._usage_store.get(p.id, 0)) for p in new_items]
        if connected is not None:
            self.connected_index = next((i for i, p in enumerate(new_items) if p.id == connected.id), None)
        self._pending_latency_indices = set(range(len(self.profiles)))
        self._save_profiles()
        self._refresh_profile_views()
        self.refresh_latencies()

    def import_from_clipboard(self) -> None:
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip()
        if not text:
            self._show_error("Clipboard is empty")
            return

        # Check if the text contains a Happ or subscription URL
        url_match = re.search(r"(happ://[^\s\"<>]+|https?://[A-Za-z0-9_.~:/?#\[\]@!$&()*+,;=-]+)", text)
        if url_match:
            candidate = url_match.group(1).rstrip("\"';,.<>")
            if is_happ_link(candidate) or is_likely_subscription_url(candidate):
                self._start_happ_import(candidate, "clipboard")
                return

        maybe_path = text
        if text.startswith("file://"):
            maybe_path = unquote(text.removeprefix("file://"))

        path_candidate = Path(maybe_path).expanduser()
        if "\n" not in maybe_path and path_candidate.is_file():
            try:
                loaded = load_profiles(path_candidate)
            except (OSError, ValueError, ConfigError):
                self._show_error(
                    "Clipboard contains a file path, but this file is not a valid text VPN config. "
                    "Copy a vless/vmess/trojan/ss link, a Happ add link, or a JSON config."
                )
                return
            self._apply_loaded_profiles(loaded)
            self._append_log(f"Imported {len(loaded)} profile(s) from clipboard path: {path_candidate}")
            self._notify_user("Profiles imported", f"Imported {len(loaded)} profile(s) from clipboard path")
            return

        try:
            loaded = load_profiles_from_text(text)
        except (ValueError, ConfigError) as exc:
            self._show_error(f"Failed to import from clipboard: {exc}")
            return

        self._apply_loaded_profiles(loaded)
        self._append_log(f"Imported {len(loaded)} profile(s) from clipboard")
        self._notify_user("Profiles imported", f"Imported {len(loaded)} profile(s) from clipboard")

    def _confirm_delete_profile(self, index: int) -> bool:
        profile = self.profiles[index]
        answer = QMessageBox.question(
            self,
            "Delete profile",
            f'Delete profile "{profile.name}"?',
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        return answer == QMessageBox.Yes

    def _delete_profile_at_index(self, index: int) -> None:
        profile = self.profiles[index]
        if self.connected_index == index:
            self.vpn.request_disconnect()

        del self.profiles[index]
        del self.profile_latencies[index]
        del self.profile_usage_bytes[index]
        self._pending_latency_indices = {
            item - 1 if item > index else item
            for item in self._pending_latency_indices
            if item != index
        }

        if self.connected_index is not None:
            if self.connected_index == index:
                self.connected_index = None
            elif self.connected_index > index:
                self.connected_index -= 1

        if profile.subscription_id:
            sub = self.subscription_store.get(profile.subscription_id)
            if sub and sub.profile_count > 0:
                sub.profile_count -= 1
                self.subscription_store.put(sub)

        self._usage_store.pop(self._profile_usage_key(profile), None)
        self._last_used_store.pop(self._profile_last_used_key(profile), None)
        self._usage_dirty = True
        self._persist_usage_store(force=True)
        self._persist_last_used_store()
        self._save_profiles()

        if not self.profiles:
            self._latency_has_results = False
            self._last_latency_update_text = "never"

        self._refresh_profile_views()
        self._append_log(f"Deleted profile: {profile.name}")
        self._notify_user("Profile deleted", profile.name)
        self.refresh_latencies()

    def delete_selected_profile(self) -> None:
        index = self._selected_profile_index()
        if index is None:
            self._show_error("Choose a profile to delete")
            return
        if self.profiles[index].subscription_id:
            self._show_error("Сервер управляется подпиской. Откройте раздел «Подписки».")
            return
        if not self._confirm_delete_profile(index):
            return
        self._delete_profile_at_index(index)

    def rename_selected_profile(self) -> None:
        index = self._selected_profile_index()
        if index is None:
            self._show_error("Choose a profile to rename")
            return
        profile = self.profiles[index]
        new_name, ok = QInputDialog.getText(self, "Rename profile", "New profile name:", text=profile.name)
        if not ok:
            return
        name = new_name.strip()
        if not name:
            self._show_error("Profile name cannot be empty")
            return
        profile.name = name
        self._save_profiles()
        self._refresh_profile_views()
        self._append_log(f"Renamed profile to: {name}")

    def _unique_profile_name(self, base_name: str) -> str:
        existing = {profile.name for profile in self.profiles}
        if base_name not in existing:
            return base_name
        counter = 2
        while True:
            candidate = f"{base_name} ({counter})"
            if candidate not in existing:
                return candidate
            counter += 1

    def duplicate_selected_profile(self) -> None:
        index = self._selected_profile_index()
        if index is None:
            self._show_error("Choose a profile to duplicate")
            return
        source = self.profiles[index]
        duplicate = Profile(
            name=self._unique_profile_name(f"{source.name} copy"),
            outbound=deepcopy(source.outbound),
            subscription_id=None,
            xray=deepcopy(source.xray),
        )
        insert_at = index + 1
        self.profiles.insert(insert_at, duplicate)
        self.profile_latencies.insert(insert_at, None)
        self.profile_usage_bytes.insert(insert_at, 0)
        self._pending_latency_indices = {item + 1 if item >= insert_at else item for item in self._pending_latency_indices}
        self._pending_latency_indices.add(insert_at)
        if self.connected_index is not None and self.connected_index >= insert_at:
            self.connected_index += 1
        self._save_profiles()
        self._refresh_profile_views()
        self._set_selected_profile_index(insert_at)
        self._append_log(f"Duplicated profile: {source.name}")
        self.refresh_latencies()

    def export_selected_profile(self) -> None:
        index = self._selected_profile_index()
        if index is None:
            self._show_error("Choose a profile to export")
            return
        profile = self.profiles[index]
        default_name = profile.name.replace("/", "_").replace("\\", "_") or "profile"
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            "Export profile",
            str(import_configs_dir() / f"{default_name}.json"),
            "JSON files (*.json);;All files (*)",
        )
        if not path_str:
            return
        target = Path(path_str)
        payload: dict[str, Any] = {"name": profile.name, "outbound": profile.outbound}
        if profile.xray:
            payload["xray"] = profile.xray
        confirmed = QMessageBox.warning(
            self, 'Export VPN credentials',
            'This configuration contains authentication credentials. Anyone with the exported '
            'file may be able to use your VPN account. Export to a private, trusted location?',
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel,
        )
        if confirmed != QMessageBox.Yes:
            return
        try:
            atomic_private_json(target, payload)
            ensure_user_owned(target)
        except OSError as exc:
            self._show_error(f"Failed to export profile: {exc}")
            return
        self._append_log(f"Exported profile to: {target}")
        self._notify_user("Profile exported", profile.name)

    def _show_profile_context_menu(self, pos) -> None:
        item = self.profile_list.itemAt(pos)
        menu = QMenu(self)
        if item is None:
            if self._profile_source == "subscriptions":
                view_action = menu.addAction("Открыть подписки")
                if menu.exec(self.profile_list.viewport().mapToGlobal(pos)) is view_action:
                    self.show_subscriptions_dialog()
            else:
                import_action = menu.addAction("Импортировать конфиг")
                paste_action = menu.addAction("Вставить из буфера")
                selected_action = menu.exec(self.profile_list.viewport().mapToGlobal(pos))
                if selected_action is import_action:
                    self.import_config()
                elif selected_action is paste_action:
                    self.import_from_clipboard()
            return

        row = self.profile_list.row(item)
        if row < 0:
            return
        data = item.data(Qt.UserRole)
        profile_index = data
        if not isinstance(profile_index, int) or profile_index >= len(self.profiles):
            return
        self._set_selected_profile_index(profile_index)
        profile = self.profiles[profile_index]

        connect_action = menu.addAction("Connect")
        update_sub_action = None
        if profile.subscription_id:
            sub = self.subscription_store.get(profile.subscription_id)
            if sub:
                update_sub_action = menu.addAction(f'Update subscription "{sub.name}"')
        rename_action = menu.addAction("Rename") if not profile.subscription_id else None
        duplicate_action = menu.addAction("Duplicate as my config")
        export_action = menu.addAction("Export")
        delete_action = menu.addAction(f'Delete "{profile.name}"') if not profile.subscription_id else None
        favorite_action = menu.addAction('Remove from favorites' if profile.id in self.favorite_profile_ids
                                         else '★ Add to favorites')
        if self.vpn.status in {"connected", "connecting"} and self.connected_index == profile_index:
            connect_action.setText("Reconnect")
        selected_action = menu.exec(self.profile_list.viewport().mapToGlobal(pos))
        if selected_action is connect_action:
            self._connect_profile(profile_index)
        elif update_sub_action and selected_action is update_sub_action:
            if profile.subscription_id:
                self.update_subscription(profile.subscription_id)
        elif rename_action and selected_action is rename_action:
            self.rename_selected_profile()
        elif selected_action is duplicate_action:
            self.duplicate_selected_profile()
        elif selected_action is export_action:
            self.export_selected_profile()
        elif delete_action and selected_action is delete_action:
            self.delete_selected_profile()
        elif selected_action is favorite_action:
            self._toggle_favorite(profile.id)

    def _toggle_favorite(self, profile_id: str) -> None:
        if profile_id in self.favorite_profile_ids:
            self.favorite_profile_ids.remove(profile_id)
        else:
            self.favorite_profile_ids.add(profile_id)
        self.settings.setValue('ui/favorites', json.dumps(sorted(self.favorite_profile_ids)))
        self._refresh_profile_views()

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
        if not self._latency_has_results:
            self._last_latency_update_text = "pending..."
        if persist:
            self._save_profiles()
        self._refresh_profile_views()
        self._set_selected_profile_index(start_index if start_index < len(self.profiles) else 0)
        self.refresh_latencies()

    def _selected_profile_index(self) -> int | None:
        item = self.profile_list.currentItem()
        if item is None:
            return None
        row = self.profile_list.currentRow()
        if row < 0:
            return None
        profile_index = item.data(Qt.UserRole)
        if not isinstance(profile_index, int) or profile_index < 0 or profile_index >= len(self.profiles):
            return None
        return profile_index

    def _connect_selected_profile(self) -> None:
        index = self._selected_profile_index()
        if index is None:
            self._show_error("Choose a profile first")
            return
        self._connect_profile(index)

    def _connect_fastest(self) -> None:
        if self.vpn.status in {'connected', 'connecting', 'disconnecting'}:
            self._stop_connection()
            return
        best = self._best_profile_index()
        if best is None:
            if not self.profiles:
                self._show_error("Choose a profile first")
            else:
                self._show_error("No latency results yet — press Ping first, then retry.")
            return
        self._connect_profile(best)

    def toggle_connection(self) -> None:
        if self.vpn.status in {'connected', 'connecting', 'disconnecting'}:
            self._stop_connection()
            return

        index = self._selected_profile_index()
        if index is None:
            # The Configs page starts on "My configs"; an account with only
            # subscription nodes still needs a working Connect button.
            quick_index = self.quick_profile_combo.currentData()
            if isinstance(quick_index, int) and 0 <= quick_index < len(self.profiles):
                index = quick_index
            elif self.profiles:
                index = 0
        if self.auto_switch_checkbox.isChecked():
            best = self._best_profile_index()
            if best is not None:
                index = best
                self._set_selected_profile_index(best)

        if index is None:
            self._show_error("Choose a profile first")
            return

        self._connect_profile(index)

    def _connect_profile(self, index: int) -> None:
        if index < 0 or index >= len(self.profiles):
            return

        routing = self._routing_options()
        if routing.mode == "only_selected" and not (routing.domains or routing.ip_cidrs):
            self._show_error("Add at least one domain or IP/CIDR for 'Proxy only listed domains/IPs' mode.")
            return
        if routing.app_mode != "disabled" and not (routing.app_process_names or routing.app_process_paths):
            self._show_error("Select at least one application in the Applications tab.")
            self._set_bottom_page(3)
            return
        if routing.dns_mode == "custom" and not routing.custom_dns.strip():
            self._show_error("Enter a Custom DNS server address.")
            return

        # No explicit stop here: VpnManager.connect_profile queues the switch
        # and restarts the session itself without blocking the GUI thread.
        self._ensure_profile_visible(index)
        self._set_selected_profile_index(index)
        switching = self.vpn.status == 'connected'
        if not switching:
            self.connected_index = index
        profile = self.profiles[index]
        self.vpn.connect_profile(profile, routing)
        if self.vpn.status == 'disconnected' and not switching:
            self.connected_index = None
        self._refresh_profile_views()

    def _routing_options(self) -> RoutingOptions:
        mode = str(self.route_mode_combo.currentData() or "all")
        domains, ip_cidrs = parse_route_targets(self.domains_edit.toPlainText())
        return RoutingOptions(
            mode=mode,
            dns_mode=str(self.dns_mode_combo.currentData() or "proxy"),
            custom_dns=self.custom_dns_edit.text().strip(),
            auto_redirect=self.auto_redirect_checkbox.isChecked(),
            include_subdomains=self.include_subdomains_checkbox.isChecked(),
            ignore_ru_domains=self.ignore_ru_domains_checkbox.isChecked(),
            domains=domains,
            ip_cidrs=ip_cidrs,
            app_mode=str(self.app_mode_combo.currentData() or "disabled"),
            app_process_names=sorted({item['name'] for item in self._selected_application_rules()
                                      if item.get('name') and not item.get('path')}),
            app_process_paths=sorted({item['path'] for item in self._selected_application_rules()
                                      if item.get('path')}),
        )

    def _on_profile_filter_changed(self) -> None:
        self._refresh_profile_views()

    def _move_profile(self, source_index: int, target_index: int) -> None:
        if source_index == target_index:
            return
        if source_index < 0 or source_index >= len(self.profiles):
            return
        if target_index < 0:
            target_index = 0
        if target_index >= len(self.profiles):
            target_index = len(self.profiles) - 1

        moved_profile = self.profiles.pop(source_index)
        moved_latency = self.profile_latencies.pop(source_index)
        moved_usage = self.profile_usage_bytes.pop(source_index)
        self.profiles.insert(target_index, moved_profile)
        self.profile_latencies.insert(target_index, moved_latency)
        self.profile_usage_bytes.insert(target_index, moved_usage)

        old_pending = self._pending_latency_indices.copy()
        self._pending_latency_indices.clear()
        for item in old_pending:
            if item == source_index:
                self._pending_latency_indices.add(target_index)
                continue
            if source_index < target_index and source_index < item <= target_index:
                self._pending_latency_indices.add(item - 1)
                continue
            if target_index <= item < source_index:
                self._pending_latency_indices.add(item + 1)
                continue
            self._pending_latency_indices.add(item)

        if self.connected_index is not None:
            if self.connected_index == source_index:
                self.connected_index = target_index
            elif source_index < target_index and source_index < self.connected_index <= target_index:
                self.connected_index -= 1
            elif target_index <= self.connected_index < source_index:
                self.connected_index += 1

    def _on_profile_items_reordered(self, old_row: int, new_row: int) -> None:
        if (self._profile_source != "manual" or
                str(self.profile_sort_combo.currentData() or "manual") != "manual" or
                self.profile_search_edit.text().strip() or self._selected_location != "ALL"):
            self._refresh_profile_views()
            return
        if not (0 <= old_row < len(self._visible_profile_indices) and
                0 <= new_row < len(self._visible_profile_indices)):
            self._refresh_profile_views()
            return
        original_idx = self._visible_profile_indices[old_row]
        target_idx = self._visible_profile_indices[new_row]
        self._move_profile(original_idx, target_idx)
        self._save_profiles()
        self._refresh_profile_views()
        self._set_selected_profile_index(target_idx)
        self._append_log("Reordered manually imported configs")

    def refresh_latencies(self) -> None:
        if not self.profiles:
            return
        if self._scan_in_progress:
            self._pending_latency_refresh = True
            self._last_latency_update_text = "scan already running..."
            self._refresh_latency_update_labels()
            return

        timeout_sec = self.timeout_spin.value() / 1000.0
        snapshot = list(self.profiles)
        self._active_scan_profile_ids = [p.id for p in snapshot]
        self._scan_in_progress = True
        self._pending_latency_refresh = False
        self._active_scan_id += 1
        scan_id = self._active_scan_id
        self._last_latency_update_text = "scanning..."
        self._refresh_latency_update_labels()
        worker = threading.Thread(
            target=self._scan_latency_worker,
            args=(scan_id, snapshot, timeout_sec),
            daemon=True,
        )
        worker.start()

    def _scan_latency_worker(self, scan_id: int, profiles: list[Profile], timeout_sec: float) -> None:
        workers = min(MAX_PROBE_WORKERS, max(2, len(profiles)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda p: profile_latency_ms(p, timeout_sec), profiles))
        self.latencies_ready.emit(scan_id, results)

        if self.vpn.status == "connected":
            res = probe_active_connection(timeout_sec=3.5)
            if res and res.get("ok"):
                ip = res.get("ip")
                loc = res.get("loc")
                latency = res.get("latency_ms")
                info = f"{latency} ms"
                if ip and loc:
                    info += f" | IP: {ip} ({loc})"
                self.worker_log.emit(f"[Probe] Active VPN latency verified: {info}")

    def _on_latencies_ready(self, scan_id: int, latencies: list[int | None]) -> None:
        if scan_id != self._active_scan_id:
            return

        self._scan_in_progress = False
        if (len(latencies) != len(self.profiles)
                or self._active_scan_profile_ids != [p.id for p in self.profiles]):
            # Subscription refresh / drag-reorder changed membership or order
            # while the asynchronous scan ran. Do not misattribute results.
            self._last_latency_update_text = 'profiles changed — rescanning...'
            self.refresh_latencies()
            return

        self.profile_latencies = latencies
        self._pending_latency_indices.clear()
        self._latency_has_results = True
        self._last_latency_update_text = time.strftime('%H:%M:%S')
        for profile, ms in zip(self.profiles, latencies):
            self.quality.record(profile.id, ms)
        self._persist_quality_store()
        if self.profile_sort_combo.currentData() in {'latency', 'quality'}:
            self._refresh_profile_views()
        else:
            self._refresh_latency_update_labels()
            self._refresh_profile_rows()
        if self.connected_index is not None and self.connected_index < len(self.profiles):
            quality = self.quality.quality(self.profiles[self.connected_index].id)
            if quality:
                jitter = f'{quality.jitter_ms:.0f}ms' if quality.jitter_ms is not None else '—'
                self.quality_status_label.setText(
                    f'Quality {quality.score:.0f}/100 • availability {quality.reliability:.0%} • jitter {jitter}')
        self._maybe_auto_switch()

        if self._pending_latency_refresh:
            self.refresh_latencies()

    def _best_profile_index(self) -> int | None:
        """Smart Connect evaluates all nodes independently of the active UI tab."""
        if not self.profiles:
            return None
        ids = [p.id for p in self.profiles]
        best = self.quality.best(ids, self.profile_latencies)
        return best if best is not None else None

    def _maybe_auto_switch(self) -> None:
        if not self.auto_switch_checkbox.isChecked() or self.vpn.status != 'connected':
            return
        if self._last_switch_scan == self._active_scan_id:
            return  # do not vote repeatedly for a stale latency scan
        self._last_switch_scan = self._active_scan_id
        current = self.connected_index
        if current is None or current >= len(self.profiles):
            return
        best = self._best_profile_index()
        if best is None or best == current:
            self._switch_candidate = None
            self._switch_candidate_votes = 0
            return
        cid = self.profiles[best].id
        if self._switch_candidate != cid:
            self._switch_candidate = cid
            self._switch_candidate_votes = 1
        else:
            self._switch_candidate_votes += 1
        if self._switch_candidate_votes < 2:
            return
        current_quality = self.quality.quality(self.profiles[current].id)
        candidate_quality = self.quality.quality(cid)
        current_rtt = self.profile_latencies[current]
        candidate_rtt = self.profile_latencies[best]
        if not should_switch(current_quality, candidate_quality,
                             current_latency=current_rtt, candidate_latency=candidate_rtt):
            return
        if time.monotonic() - self._last_auto_switch < 90.0:
            return
        self._last_auto_switch = time.monotonic()
        self._switch_candidate_votes = 0
        self._append_log(f'Smart Connect: testing a switch to {self.profiles[best].name}; '
                         'the current tunnel remains active during preflight')
        self._connect_profile(best)

    def _on_traffic_tick(self) -> None:
        now = time.monotonic()
        if self.vpn.status != 'connected' or self.connected_index is None or self.connected_index >= len(self.profiles):
            self._traffic_last_total = None
            self._last_traffic_counters = None
            self._last_traffic_sample = now
            self.traffic_label.setText('↓ 0 B/s     ↑ 0 B/s')
            return
        counters = self._read_interface_counters()
        if counters is None:
            return
        previous, self._last_traffic_counters = self._last_traffic_counters, counters
        elapsed = max(0.2, now - self._last_traffic_sample)
        self._last_traffic_sample = now
        if previous is None:
            return
        down = max(0, counters[0] - previous[0])
        up = max(0, counters[1] - previous[1])
        self.traffic_chart.add_sample(down / elapsed, up / elapsed)
        self.traffic_label.setText(
            f'↓ {self._format_bytes(int(down / elapsed))}/s     '
            f'↑ {self._format_bytes(int(up / elapsed))}/s')
        if down + up == 0:
            return
        idx = self.connected_index
        self.profile_usage_bytes[idx] += down + up
        self._usage_store[self.profiles[idx].id] = self.profile_usage_bytes[idx]
        self._usage_dirty = True
        self._refresh_profile_rows(idx)
        self._persist_usage_store()

    def _connection_warmup_worker(self) -> None:
        time.sleep(0.3)
        res = probe_active_connection(timeout_sec=4.0)
        if res and res.get("ok"):
            ip = res.get("ip")
            loc = res.get("loc")
            latency = res.get("latency_ms")
            info = f"{latency} ms"
            if ip and loc:
                info += f" | IP: {ip} ({loc})"
            self.worker_log.emit(f"[Probe] Tunnel warm-up successful: {info}")
        else:
            time.sleep(0.8)
            res2 = probe_active_connection(timeout_sec=4.0)
            if res2 and res2.get("ok"):
                self.worker_log.emit(f"[Probe] Tunnel verified: {res2.get('latency_ms')} ms")

    def _on_vpn_profile_starting(self, profile: object) -> None:
        if not isinstance(profile, Profile):
            return
        self._desired_profile_id = profile.id
        index = next((i for i, p in enumerate(self.profiles) if p.id == profile.id), None)
        if index is not None:
            self.connected_index = index
            self._touch_profile_last_used(index)
        self._refresh_profile_rows()
        self._update_tray_menu()

    def _stop_connection(self) -> None:
        self._desired_profile_id = None
        self._reconnect_timer.stop()
        self._reconnect_attempts = 0
        self.vpn.request_disconnect()

    def _on_connection_lost(self, reason: str) -> None:
        if not self.auto_reconnect_checkbox.isChecked() or not self._desired_profile_id:
            return
        if self._reconnect_attempts >= 5:
            self._append_log('Automatic recovery stopped after five attempts. Check diagnostics.')
            self._notify_user('Connection lost', 'Automatic recovery exhausted; reconnect manually.')
            return
        delay = min(45, 2 ** (self._reconnect_attempts + 1))
        self._reconnect_attempts += 1
        self._append_log(f'{reason}; retry {self._reconnect_attempts}/5 in {delay} seconds')
        self._reconnect_timer.start(delay * 1000)

    def _attempt_reconnect(self) -> None:
        if self.vpn.status != 'disconnected' or not self._desired_profile_id:
            return
        index = next((i for i, p in enumerate(self.profiles) if p.id == self._desired_profile_id), None)
        if index is not None:
            self._connect_profile(index)

    def run_diagnostics(self) -> None:
        if self._diag_running:
            return
        self._diag_running = True
        self.diag_run_btn.setEnabled(False)
        self.diagnostic_summary.setText('Running safe tunnel checks...')
        connected = self.vpn.status == 'connected'
        pid = int(self.vpn.process.processId()) if connected else None

        def worker() -> None:
            try:
                data = connected_diagnostics(connected=connected, interface=IFACE_NAME,
                                             process_pid=pid)
            except Exception as exc:
                data = {'error': redact(str(exc)), 'vpn_running': connected}
            self.diagnostics_ready.emit(data)

        threading.Thread(target=worker, daemon=True).start()

    def _on_diagnostics_ready(self, data: object) -> None:
        self._diag_running = False
        self.diag_run_btn.setEnabled(True)
        if not isinstance(data, dict):
            data = {'error': 'Invalid diagnostics response'}
        safe = redacted_structure(data)
        self.diag_details.setPlainText(json.dumps(safe, indent=2, ensure_ascii=False))
        if safe.get('external_ip'):
            self.diagnostic_summary.setText(
                f"TUN: {'up' if safe.get('interface_up') else 'down'} • "
                f"External IP: {safe['external_ip']} • "
                f"RTT: {safe.get('latency_ms') or '—'} ms • "
                f"DNS: {'OK' if safe.get('dns_ok') else 'FAILED'}")
        else:
            self.diagnostic_summary.setText(str(safe.get('message') or safe.get('error') or 'Connection not verified'))

    def copy_diagnostic_report(self) -> None:
        text = self.diag_details.toPlainText() or 'No diagnostics collected yet.'
        QApplication.clipboard().setText(redact(text))
        self._notify_user('Diagnostics', 'Sanitized connection report copied.')

    def _on_vpn_status_changed(self, status: str) -> None:
        self._last_vpn_status = status
        self._set_status(status)
        self._refresh_profile_views()
        if status == 'connected':
            self._reconnect_attempts = 0
            if self.connected_index is not None:
                threading.Thread(target=self._connection_warmup_worker, daemon=True).start()
        elif status == 'disconnected':
            self.connected_index = None
            self._timeout_streak = 0
            self._traffic_last_total = None
            self._last_traffic_counters = None
            self.traffic_chart.reset()
            self._persist_usage_store(force=True)
        self._update_tray_menu()

    def _set_status(self, status: str) -> None:
        mapping = {
            "disconnected": ("Не подключено", "statusDisconnected", "Подключить"),
            "connecting": ("Подключаемся…", "statusConnecting", "Отменить"),
            "connected": ("Защищённое соединение", "statusConnected", "Отключить"),
            "disconnecting": ("Отключаемся…", "statusDisconnecting", "Отключить"),
        }
        status_text, _, button_text = mapping.get(status, (status, "statusDisconnected", "Connect"))
        self.connect_btn.setText(button_text)
        self.connect_btn.setProperty("vpnState", "connected" if status == "connected" else "disconnected")
        self.connect_btn.style().unpolish(self.connect_btn)
        self.connect_btn.style().polish(self.connect_btn)
        dot_colors = {
            "disconnected": "#6b7280",
            "connecting": "#e0a34e",
            "connected": "#4bd3b2",
            "disconnecting": "#e0a34e",
        }
        self.status_dot.setStyleSheet(f"color: {dot_colors.get(status, '#6b7280')}; font-size: 16px;")
        self.status_label.setText(status_text)
        self._update_vpn_profile_label()
        self._update_status_bar()

    def _update_vpn_profile_label(self) -> None:
        if not self.profiles:
            self.vpn_profile_label.setText("Добавьте подписку или конфиг")
            return
        if self.vpn.status in {"connected", "connecting"} and self.connected_index is not None:
            index = self.connected_index
        else:
            index = self._selected_profile_index()
            if index is None:
                quick_index = self.quick_profile_combo.currentData()
                index = quick_index if isinstance(quick_index, int) else None
        if index is None or index < 0 or index >= len(self.profiles):
            self.vpn_profile_label.setText(f"{len(self.profiles)} profile(s) available")
            return
        profile = self.profiles[index]
        latency = self.profile_latencies[index] if index < len(self.profile_latencies) else None
        if not self._latency_has_results:
            latency_text = "checking..."
        else:
            latency_text = "timeout" if latency is None else f"{latency} ms"
        prefix = "Active: " if self.vpn.status in {"connected", "connecting"} else ""
        self.vpn_profile_label.setText(f"{prefix}{profile.name} · {latency_text}")

    def _update_status_bar(self) -> None:
        status_text = self.status_label.text() if hasattr(self, "status_label") else "—"
        sub_count = len(self.subscription_store.all())
        self.statusBar().showMessage(f"{status_text} • {len(self.profiles)} profiles • {sub_count} subscriptions")

    def copy_logs(self) -> None:
        QApplication.clipboard().setText(redact(self.logs.toPlainText()))
        self._notify_user("Logs copied", "Current logs copied to clipboard")

    def clear_logs(self) -> None:
        self.logs.clear()
        self._append_log("Logs cleared")

    def open_log_file(self) -> None:
        path = log_path()
        if not path.exists():
            try:
                path.touch()
                path.chmod(0o600)
                ensure_user_owned(path)
            except OSError as exc:
                self._show_error(f"Failed to prepare log file: {exc}")
                return
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        if not opened:
            self._show_error(f"Failed to open log file: {path}")
            return
        self._append_log(f"Opened log file: {path}")
        self._notify_user("Log file", str(path))

    def _append_log(self, text: str) -> None:
        safe = redact(text)
        self.logs.appendPlainText(safe)
        logging.info(safe)

    def event(self, event) -> bool:  # type: ignore[override]
        if event.type() == QEvent.Type.FileOpen:
            url = event.url()
            if url.scheme().lower() in {"happ", "http", "https"}:
                link = url.toString()
                QTimer.singleShot(0, lambda value=link: self._start_happ_import(value, "deep link"))
                return True
        return super().event(event)

    def _show_error(self, message: str) -> None:
        safe = redact(message)
        QMessageBox.critical(self, 'Error', safe)
        self._append_log(f'ERROR: {safe}')

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._persist_usage_store(force=True)
        self._persist_last_used_store()
        self._persist_quality_store(force=True)
        self._reconnect_timer.stop()
        self.settings.sync()
        self._protect_settings_file()
        self._subscription_pool.shutdown(wait=False, cancel_futures=True)
        self.vpn.disconnect()
        super().closeEvent(event)

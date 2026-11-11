"""Offscreen Qt regression checks for the real compact window (in CI)."""
import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
pytest.importorskip('PySide6')
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.desktop_apps import DesktopApp
from app.main_window import MainWindow


@pytest.fixture(scope='module')
def app():
    instance = QApplication.instance()
    owned = instance is None
    instance = instance or QApplication([])
    yield instance
    if owned:
        instance.quit()


@pytest.fixture
def ui(app, monkeypatch, tmp_path):
    # Prevent any system changes, dialogs and network actions in the smoke test.
    monkeypatch.setattr('app.app_paths._home_dir', lambda: tmp_path)
    monkeypatch.setattr('app.net_session.reconcile_stale_session', lambda: None)
    monkeypatch.setattr(MainWindow, '_setup_sleep_monitor', lambda self: None)
    monkeypatch.setattr(MainWindow, '_setup_instance_server', lambda self: None)
    monkeypatch.setattr(MainWindow, '_warn_if_not_running_as_sudo', lambda self: None)
    monkeypatch.setattr('app.vpn_manager.VpnManager.refresh_singbox_availability', lambda self: None)
    monkeypatch.setattr('app.main_window.installed_applications', lambda: [
        DesktopApp('Mozilla Firefox', '/usr/bin/firefox', 'firefox', 'firefox'),
        DesktopApp('Telegram Desktop', '/usr/bin/telegram-desktop', 'telegram-desktop', 'telegram'),
    ])
    monkeypatch.setattr('app.main_window.running_applications', lambda: [])
    window = MainWindow()
    window.show()
    app.processEvents()
    yield window
    window.close()
    app.processEvents()


def test_main_navigation_has_single_compact_footer(ui, app):
    assert ui.width() == 520
    assert len(ui.nav_buttons) == 3
    assert ui.bottom_nav.isVisible()
    assert ui.bottom_nav.height() == 44
    assert all(button.height() == 34 for button in [*ui.nav_buttons, ui.more_btn])
    assert all(not button.icon().isNull() for button in [*ui.nav_buttons, ui.more_btn])
    assert ui.app_quick_btn.isVisible()
    ui._set_bottom_page(3)
    app.processEvents()
    assert ui.application_list.isVisible()
    assert all(button.isVisible() for button in ui.app_mode_buttons.values())


def test_application_rows_have_icons_and_clicking_auto_enables_proxy_selected(ui):
    ui._set_bottom_page(3)
    assert ui.application_list.count() == 2
    row = ui.application_list.item(0)
    assert not row.icon().isNull()
    assert row.checkState() == Qt.Unchecked
    row.setCheckState(Qt.Checked)
    assert ui.app_mode_combo.currentData() == 'proxy_selected'
    rules = ui._selected_application_rules()
    assert len(rules) == 1 and rules[0]['path']
    assert not rules[0]['name']  # precise path match instead of broad process name
    assert '1' in ui.app_selection_label.text()
    assert '1' in ui.app_quick_btn.text()
    row.setCheckState(Qt.Unchecked)
    assert ui.app_mode_combo.currentData() == 'disabled'


def test_application_screen_stays_within_narrow_window(ui, app):
    ui.resize(400, 595)
    ui._set_bottom_page(3)
    app.processEvents()
    assert ui.width() >= 400
    assert ui.application_list.height() >= 40
    for button in ui.app_mode_buttons.values():
        assert button.geometry().right() <= ui.width()


def test_global_ru_bypass_is_visible_persistent_and_survives_presets(ui, app):
    ui._set_bottom_page(0)
    app.processEvents()
    checkbox = ui.ignore_ru_domains_checkbox
    assert checkbox.isVisible()
    assert checkbox.isEnabled()
    assert 'ru' in checkbox.text()
    checkbox.setChecked(True)
    assert ui.settings.value('route_ignore_ru_domains', False, type=bool)

    # Changing presets must not silently turn off the global policy.
    ui._set_bottom_page(6)
    ui.preset_combo.setCurrentIndex(ui.preset_combo.findData('all'))
    ui._apply_route_preset()
    assert checkbox.isChecked()
    ui._set_bottom_page(3)
    ui.application_list.item(0).setCheckState(Qt.Checked)
    assert ui._routing_options().ignore_ru_domains


@pytest.mark.parametrize('width,height', [(380, 550), (400, 595), (520, 690), (720, 780)])
def test_compact_footer_never_clips_and_preserves_navigation(ui, app, width, height):
    ui.resize(width, height)
    ui.show()
    for page in (0, 1, 6, 3, 2, 5, 4):
        ui._set_bottom_page(page)
        app.processEvents()
        rect = ui.bottom_nav.geometry()
        assert rect.right() <= ui.centralWidget().width()
        assert rect.bottom() <= ui.centralWidget().height()
        assert ui.bottom_nav.height() == 44
        for button in [*ui.nav_buttons, ui.more_btn]:
            assert button.height() == 34
            assert button.geometry().right() < ui.bottom_nav.width()
        assert ui.more_btn.isChecked() == (page not in (0, 1, 6))

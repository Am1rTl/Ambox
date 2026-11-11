"""Render repeatable screenshots of the real PySide6 UI, without network or root.

Usage (Linux, with PySide6 installed):
    QT_QPA_PLATFORM=offscreen python tools/capture_ui.py --output screenshots/

Used by CI to catch layout regressions; never invokes a VPN connection.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication

from app.config_parser import Profile
from app.desktop_apps import DesktopApp
from app.main_window import MainWindow
from app.subscriptions import Subscription


def render(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory(prefix='ambox-ui-') as temp, \
         patch('app.app_paths._home_dir', lambda: Path(temp)), \
         patch('app.net_session.reconcile_stale_session', lambda: None), \
         patch.object(MainWindow, '_setup_sleep_monitor', lambda self: None), \
         patch.object(MainWindow, '_setup_instance_server', lambda self: None), \
         patch.object(MainWindow, '_warn_if_not_running_as_sudo', lambda self: None), \
         patch('app.vpn_manager.VpnManager.refresh_singbox_availability', lambda self: None), \
         patch('app.main_window.installed_applications', lambda: [
             DesktopApp('Firefox', '/usr/bin/firefox', 'firefox', 'firefox'),
             DesktopApp('Telegram Desktop', '/usr/bin/telegram-desktop', 'telegram-desktop', 'telegram'),
             DesktopApp('Visual Studio Code', '/usr/bin/code', 'code', 'code'),
         ]), \
         patch('app.main_window.running_applications', lambda: []):
        window = MainWindow()
        try:
            window.profiles = [
                Profile('🇩🇪 Frankfurt · Main', {'type': 'socks', 'server': '127.0.0.1', 'server_port': 1080}),
                Profile('🇳🇱 Amsterdam · Fast', {'type': 'socks', 'server': '127.0.0.1', 'server_port': 1081}),
            ]
            window.profile_latencies = [45, 66]
            window.profile_usage_bytes = [0, 0]
            window.subscription_store.put(Subscription(
                id='preview-sub', name='Demo subscription',
                url='https://example.invalid/demo', profile_count=8,
                updated_at=0, user_info={'upload': 100000, 'download': 1240000000, 'total': 10000000000}
            ))
            window._refresh_profile_views()
            window._sync_quick_profile_selector()
            window.subscriptions_panel.refresh_list()
            pages = {'vpn': 0, 'configs': 1, 'subscriptions': 6, 'apps': 3}
            for size in ((380, 550), (520, 690), (720, 780)):
                window.resize(*size)
                window.show()
                app.processEvents()
                for name, page in pages.items():
                    window._set_bottom_page(page)
                    app.processEvents()
                    file = output / f'{name}_{size[0]}x{size[1]}.png'
                    shot = window.grab()
                    if not shot.save(str(file)):
                        raise RuntimeError(f'Screenshot failed: {file}')
                    # Theme regressions used to show giant white blocks on tall windows.
                    if name in ('vpn', 'subscriptions') and size[1] >= 690:
                        pixel = shot.toImage().pixelColor(size[0] // 2, size[1] - 86)
                        assert pixel.lightness() < 80, (name, size, pixel.name())
                    # A screenshot alone can hide clipping: fail CI on bad footer geometry.
                    nav_rect = window.bottom_nav.geometry()
                    assert window.bottom_nav.height() == 44, (name, size, nav_rect)
                    assert nav_rect.left() >= 0 and nav_rect.right() <= window.centralWidget().width()
                    for btn in [*window.nav_buttons, window.more_btn]:
                        assert btn.height() == 34
                        assert btn.geometry().left() >= 0
                        assert btn.geometry().right() <= window.bottom_nav.width()
                    print(file)
        finally:
            window.close()
            app.processEvents()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('screenshots'))
    args = parser.parse_args()
    render(args.output)

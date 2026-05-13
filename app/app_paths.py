from __future__ import annotations

import os
import platform
from pathlib import Path

APP_DIR_NAME = "ambox"


def app_data_dir() -> Path:
    system = platform.system().lower()
    if system == "windows":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else (Path.home() / "AppData" / "Roaming")
        return base / APP_DIR_NAME
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    return Path.home() / f".{APP_DIR_NAME}"


def ensure_app_data_dir() -> Path:
    path = app_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            path.chmod(0o700)
        except OSError:
            pass
    return path


def settings_path() -> Path:
    return ensure_app_data_dir() / "settings.ini"


def log_path() -> Path:
    return ensure_app_data_dir() / "app.log"


def active_config_path() -> Path:
    return ensure_app_data_dir() / "active-config.json"


def profiles_path() -> Path:
    return ensure_app_data_dir() / "profiles.json"


def singbox_cache_path() -> Path:
    return ensure_app_data_dir() / "cache.db"

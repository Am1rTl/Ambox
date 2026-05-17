from __future__ import annotations

import os
import platform
from pathlib import Path

try:
    import pwd
except ImportError:  # pragma: no cover - Windows has no pwd module.
    pwd = None

APP_DIR_NAME = "ambox"


def _sudo_user_record():
    if os.name != "posix" or pwd is None:
        return None
    try:
        if os.geteuid() != 0:
            return None
    except AttributeError:
        return None

    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return None

    try:
        return pwd.getpwnam(sudo_user)
    except KeyError:
        return None


def _home_dir() -> Path:
    sudo_record = _sudo_user_record()
    if sudo_record is not None and sudo_record.pw_dir:
        return Path(sudo_record.pw_dir)
    return Path.home()


def ensure_user_owned(path: Path) -> None:
    sudo_record = _sudo_user_record()
    if sudo_record is None or not path.exists():
        return
    try:
        os.chown(path, sudo_record.pw_uid, sudo_record.pw_gid)
    except OSError:
        pass


def app_data_dir() -> Path:
    system = platform.system().lower()
    home = _home_dir()
    if system == "windows":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else (home / "AppData" / "Roaming")
        return base / APP_DIR_NAME
    if system == "darwin":
        return home / "Library" / "Application Support" / APP_DIR_NAME
    return home / f".{APP_DIR_NAME}"


def ensure_app_data_dir() -> Path:
    path = app_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        ensure_user_owned(path)
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


def import_configs_dir() -> Path:
    path = ensure_app_data_dir() / "imports"
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        ensure_user_owned(path)
        try:
            path.chmod(0o700)
        except OSError:
            pass
    return path

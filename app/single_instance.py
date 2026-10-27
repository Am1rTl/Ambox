"""Single-instance enforcement.

The first instance holds a QLockFile and serves a QLocalServer; a second copy
notifies it (show window, optionally import a happ:// link) and exits instead
of fighting over the TUN interface, routing table and active-config.json.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QLockFile
from PySide6.QtNetwork import QLocalSocket

from app.app_paths import ensure_app_data_dir

SERVER_NAME = "ambox-single-instance"
SHOW_MESSAGE = "show"
LINK_PREFIX = "link:"


def lock_file_path() -> Path:
    return ensure_app_data_dir() / "app.lock"


class SingleInstanceGuard:
    """Holds the instance lock for the whole application lifetime."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._lock = QLockFile(str(path or lock_file_path()))
        self._lock.setStaleLockTime(5000)

    def try_acquire(self) -> bool:
        try:
            # PySide6 exposes no default arg: 0 = do not block.
            return bool(self._lock.tryLock(0))
        except (OSError, RuntimeError) as exc:
            logging.warning("Instance lock failed: %s", exc)
            return False

    def release(self) -> None:
        try:
            self._lock.unlock()
        except (OSError, RuntimeError):
            pass


def notify_running_instance(link: str | None = None) -> bool:
    """Ask the running instance to show itself (and import a link)."""
    sock = QLocalSocket()
    try:
        sock.connectToServer(SERVER_NAME)
        if not sock.waitForConnected(2000):
            return False
        message = f"{LINK_PREFIX}{link}" if link else SHOW_MESSAGE
        sock.write(message.encode("utf-8"))
        if not sock.waitForBytesWritten(2000):
            return False
        sock.disconnectFromServer()
        return True
    finally:
        sock.close()

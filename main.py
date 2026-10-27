from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import traceback
from logging.handlers import RotatingFileHandler

from PySide6.QtCore import QSocketNotifier, QTimer
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QMessageBox

from app.app_paths import log_path
from app.main_window import MainWindow


_DAEMON_ENV = "AMBOX_DAEMONIZED"


def _relaunch_detached() -> None:
    """
    PyInstaller one-file builds run Python as a child of a bootloader that deletes the unpacked
    /tmp/_MEI* directory once that child exits. A forked daemon would outlive it and then fail on
    every lazy import (e.g. subscription updates: "No such file .../base_library.zip"), so the
    frozen app starts a fresh, detached copy of itself that unpacks its own files instead.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith(("_MEI", "_PYI"))}
    env[_DAEMON_ENV] = "1"
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    original_ld = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if original_ld is not None:
        env["LD_LIBRARY_PATH"] = original_ld
    else:
        env.pop("LD_LIBRARY_PATH", None)
    subprocess.Popen(
        [sys.executable, *sys.argv[1:]],
        env=env,
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    os._exit(0)


def _daemonize() -> None:
    if os.environ.pop(_DAEMON_ENV, None) == "1":
        return
    if getattr(sys, "frozen", False):
        _relaunch_detached()
    if not hasattr(os, "fork"):  # e.g. Windows: no fork, stay in foreground
        return
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    os.chdir("/")
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, "w") as null:
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            try:
                os.dup2(null.fileno(), stream.fileno())
            except (AttributeError, ValueError, OSError):
                continue  # stream has no usable fd (e.g. launched without a terminal)


def _configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    # sing-box logs every connection; without rotation the file grows by gigabytes.
    handlers: list[logging.Handler] = []
    try:
        app_log_path = log_path()
        handlers.append(
            RotatingFileHandler(app_log_path, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8")
        )
    except OSError as exc:
        # Log dir/file may be unwritable (e.g. root-owned after a sudo run):
        # stay alive and log to stderr instead of crashing at startup.
        print(f"warning: cannot write log file: {exc}; logging to stderr", file=sys.stderr)
    if debug or not handlers:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )
    logging.info("Application started. debug=%s", debug)


def _install_signal_wakeup(app: QApplication) -> object:
    """Quit through Qt on SIGTERM/SIGINT/SIGHUP so VpnManager tears down TUN cleanly.

    Python signal handlers only run when the interpreter regains control, which a
    bare Qt event loop never yields. A wakeup fd + QSocketNotifier wakes the loop
    on any signal instead of polling with a QTimer. Falls back to a 500ms QTimer
    where socketpair/wakeup-fd is unavailable. The caller must keep the returned
    guard alive for the whole application lifetime.
    """
    watched = [signal.SIGTERM, signal.SIGINT]
    sighup = getattr(signal, "SIGHUP", None)  # missing on Windows
    if sighup is not None:
        watched.append(sighup)
    for sig in watched:
        try:
            signal.signal(sig, lambda *_args: app.quit())
        except (OSError, ValueError):
            continue

    if os.name == "posix":
        try:
            import socket as _socket

            rsock, wsock = _socket.socketpair()
            rsock.setblocking(False)
            wsock.setblocking(False)
            signal.set_wakeup_fd(wsock.fileno(), warn_on_full_buffer=False)
        except (OSError, ValueError):
            pass
        else:
            notifier = QSocketNotifier(rsock.fileno(), QSocketNotifier.Type.Read)

            def _drain() -> None:
                try:
                    rsock.recv(1024)
                except OSError:
                    pass

            notifier.activated.connect(lambda *_args: _drain())
            notifier.setEnabled(True)
            return (notifier, rsock, wsock)

    keepalive = QTimer()
    keepalive.start(500)
    keepalive.timeout.connect(lambda: None)
    return keepalive


def _install_excepthook(debug: bool) -> None:
    def _hook(exc_type, exc_value, exc_tb) -> None:
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logging.error("Unhandled exception:\n%s", text)
        if debug:
            print(text, file=sys.stderr, flush=True)
        QMessageBox.critical(None, "Unhandled Error", f"{exc_type.__name__}: {exc_value}")

    sys.excepthook = _hook


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ambox")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode with verbose logs and traceback output",
    )
    parser.add_argument(
        "-f",
        "--foreground",
        action="store_true",
        help="Stay in the foreground (skip daemonization), e.g. for debugging",
    )
    parser.add_argument(
        "link",
        nargs="?",
        help="Optional happ:// link to import at startup",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    if not args.foreground:
        _daemonize()

    if args.debug:
        os.environ.setdefault("QT_LOGGING_RULES", "*.debug=true")

    _configure_logging(args.debug)
    app = QApplication([sys.argv[0]])
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#111621"))
    palette.setColor(QPalette.WindowText, QColor("#d9dce3"))
    palette.setColor(QPalette.Base, QColor("#0f1119"))
    palette.setColor(QPalette.AlternateBase, QColor("#1c202b"))
    palette.setColor(QPalette.ToolTipBase, QColor("#1c202b"))
    palette.setColor(QPalette.ToolTipText, QColor("#d9dce3"))
    palette.setColor(QPalette.Text, QColor("#d9dce3"))
    palette.setColor(QPalette.Button, QColor("#1c202b"))
    palette.setColor(QPalette.ButtonText, QColor("#d9dce3"))
    palette.setColor(QPalette.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.Link, QColor("#f0b774"))
    palette.setColor(QPalette.Highlight, QColor("#3a3027"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)
    app.setStyleSheet("QToolTip { background-color: #1c202b; border: 1px solid #3a3f4d; color: #d9dce3; }")
    _install_excepthook(args.debug)
    window = MainWindow(initial_link=args.link)
    window.show()
    app.aboutToQuit.connect(window.vpn.disconnect)
    _signal_guard = _install_signal_wakeup(app)
    logging.info("Main window initialized")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

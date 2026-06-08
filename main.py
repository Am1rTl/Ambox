from __future__ import annotations

import argparse
import logging
import os
import sys
import traceback

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QMessageBox

from app.app_paths import log_path
from app.main_window import MainWindow


def _daemonize() -> None:
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    os.chdir("/")
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, "w") as null:
        os.dup2(null.fileno(), sys.stdin.fileno())
        os.dup2(null.fileno(), sys.stdout.fileno())
        os.dup2(null.fileno(), sys.stderr.fileno())


def _configure_logging(debug: bool) -> None:
    app_log_path = log_path()

    level = logging.DEBUG if debug else logging.INFO
    handlers: list[logging.Handler] = [logging.FileHandler(app_log_path, encoding="utf-8")]
    if debug:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )
    logging.info("Application started. debug=%s", debug)


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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
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
    window = MainWindow()
    window.show()
    logging.info("Main window initialized")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

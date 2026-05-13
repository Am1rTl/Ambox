from __future__ import annotations

import argparse
import logging
import os
import sys
import traceback

from PySide6.QtWidgets import QApplication, QMessageBox

from app.app_paths import log_path
from app.main_window import MainWindow


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
    if args.debug:
        os.environ.setdefault("QT_LOGGING_RULES", "*.debug=true")

    _configure_logging(args.debug)
    app = QApplication([sys.argv[0]])
    _install_excepthook(args.debug)
    window = MainWindow()
    window.show()
    logging.info("Main window initialized")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

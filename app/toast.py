from __future__ import annotations

from PySide6.QtCore import QPropertyAnimation, QRect, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QVBoxLayout, QWidget


class ToastNotification(QWidget):
    PADDING = 20
    WIDTH = 320
    MARGIN = 24

    def __init__(
        self,
        title: str,
        message: str,
        is_connected: bool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setFixedWidth(self.WIDTH)

        accent = QColor("#4a9e6a") if is_connected else QColor("#e05a5a")

        outer = QWidget(self)
        outer.setObjectName("toastOuter")
        outer.setStyleSheet(f"""
            #toastOuter {{
                background-color: #1a1e2c;
                border: 1px solid {accent.name()};
                border-radius: 12px;
            }}
        """)

        shadow = QVBoxLayout(self)
        shadow.setContentsMargins(8, 8, 8, 8)
        shadow.addWidget(outer)

        layout = QHBoxLayout(outer)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        icon_label = QLabel()
        icon_label.setFixedSize(28, 28)
        pixmap = QPixmap(28, 28)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(accent)
        painter.drawRoundedRect(2, 2, 24, 24, 8, 8)

        font = QFont()
        font.setPixelSize(15)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(2, 2, 24, 24, Qt.AlignCenter, "✓" if is_connected else "✕")
        painter.end()
        icon_label.setPixmap(pixmap)
        layout.addWidget(icon_label, 0, Qt.AlignTop)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {accent.name()}; font-weight: 700; font-size: 13px; background: transparent;")
        text_layout.addWidget(title_label)

        msg_label = QLabel(message)
        msg_label.setStyleSheet("color: #b6bfce; font-size: 12px; background: transparent;")
        msg_label.setWordWrap(True)
        text_layout.addWidget(msg_label)

        layout.addLayout(text_layout, 1)

        self.adjustSize()
        self._position()

        QTimer.singleShot(3500, self._fade_out)

    def _position(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        geo = screen.availableGeometry()
        x = geo.right() - self.width() - self.MARGIN
        y = geo.bottom() - self.height() - self.MARGIN
        self.move(x, y + 40)
        self.show()

        anim = QPropertyAnimation(self, b"geometry")
        anim.setDuration(300)
        anim.setStartValue(QRect(x + 60, y + 40, self.width(), self.height()))
        anim.setEndValue(QRect(x, y + 40, self.width(), self.height()))
        anim.start()
        self._anim = anim

    def _fade_out(self) -> None:
        anim = QPropertyAnimation(self, b"windowOpacity")
        anim.setDuration(250)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.finished.connect(self.close)
        anim.start()
        self._fade_anim = anim

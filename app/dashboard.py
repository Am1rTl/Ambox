"""Lightweight self-drawn traffic chart; no charting dependencies."""
from __future__ import annotations

from collections import deque
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget


class TrafficChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._download: deque[float] = deque(maxlen=90)
        self._upload: deque[float] = deque(maxlen=90)
        self.setMinimumHeight(95)

    def add_sample(self, rx_bps: float, tx_bps: float) -> None:
        self._download.append(max(0.0, rx_bps))
        self._upload.append(max(0.0, tx_bps))
        self.update()

    def reset(self) -> None:
        self._download.clear()
        self._upload.clear()
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        painter.fillRect(self.rect(), QColor('#111b27'))
        pad = 10
        painter.setPen(QPen(QColor('#263242'), 1))
        for j in range(1, 4):
            y = int(h * j / 4)
            painter.drawLine(pad, y, w - pad, y)
        maximum = max([1024.0, *self._download, *self._upload])
        for values, color in ((self._download, '#55d8b0'), (self._upload, '#7d9fff')):
            if not values:
                continue
            path = QPainterPath()
            for i, value in enumerate(values):
                x = pad + (w - 2 * pad) * i / max(1, values.maxlen - 1)
                y = h - pad - (h - 2 * pad) * float(value) / maximum
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            painter.setPen(QPen(QColor(color), 2))
            painter.drawPath(path)
        painter.end()

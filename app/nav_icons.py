"""Small vector icons for Ambox's navigation, painted at high DPI.

Kept in code to avoid extra fonts, assets or icon theme dependencies.
"""
from __future__ import annotations

from PySide6.QtCore import QLineF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap


def _pixmap(name: str, color: str) -> QPixmap:
    pix = QPixmap(40, 40)
    pix.setDevicePixelRatio(2.0)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor(color), 1.7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    if name == 'vpn':
        p.drawArc(QRectF(3.9, 3.9, 12.2, 12.2), 132 * 16, 276 * 16)
        p.drawLine(QLineF(10, 2.7, 10, 10.5))
    elif name == 'configs':
        p.drawRoundedRect(QRectF(4, 3.5, 12, 5), 1.4, 1.4)
        p.drawRoundedRect(QRectF(4, 11.5, 12, 5), 1.4, 1.4)
        p.drawLine(QLineF(6.5, 6.0, 9.5, 6.0))
        p.drawLine(QLineF(6.5, 14.0, 9.5, 14.0))
    elif name == 'subscriptions':
        p.drawRoundedRect(QRectF(3.2, 5.0, 7.3, 9.2), 3.4, 3.4)
        p.drawRoundedRect(QRectF(9.5, 5.8, 7.3, 9.2), 3.4, 3.4)
        p.drawLine(QLineF(8.5, 10, 11.5, 10))
    elif name == 'more':
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(color))
        for x in (4.3, 10.0, 15.7):
            p.drawEllipse(QRectF(x-1.45, 8.55, 2.9, 2.9))
    p.end()
    return pix


def navigation_icon(name: str) -> QIcon:
    """Provide explicit normal/selected pixmaps, even without an icon theme."""
    if name not in ('vpn', 'configs', 'subscriptions', 'more'):
        raise ValueError(f'Unknown navigation icon: {name}')
    icon = QIcon()
    icon.addPixmap(_pixmap(name, '#94a8b9'), QIcon.Normal, QIcon.Off)
    icon.addPixmap(_pixmap(name, '#80ebcd'), QIcon.Normal, QIcon.On)
    icon.addPixmap(_pixmap(name, '#e3f4f0'), QIcon.Active, QIcon.Off)
    icon.addPixmap(_pixmap(name, '#80ebcd'), QIcon.Active, QIcon.On)
    return icon

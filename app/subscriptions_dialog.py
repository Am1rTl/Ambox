from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING
from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.subscriptions import Subscription, SubscriptionStore, format_bytes

if TYPE_CHECKING:
    from app.main_window import MainWindow


class SubscriptionCard(QWidget):
    """Compact one-row subscription card: name, status, traffic bar, remaining."""

    update_requested = Signal(str)
    rename_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, sub: Subscription, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.sub_id = sub.id
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)

        stats = sub.traffic_stats()
        name = QLabel(f"📌 {sub.name}")
        name.setStyleSheet("font-weight: 700; color: #f0f1f5; font-size: 13px;")
        name.setToolTip(sub.name)
        # Long names must shrink (clip) instead of pushing the buttons out.
        name.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        top_row.addWidget(name, 1)

        button_style = (
            "QPushButton { background-color: #22293a; border: 1px solid #3d475f;"
            " border-radius: 6px; padding: 2px 10px; color: #dfe3ec; font-size: 11px; }"
            "QPushButton:hover { background-color: #2c3550; border-color: #f3b66a; }"
        )
        delete_style = button_style.replace("#dfe3ec", "#ff8a8a")
        for label, tip, signal, style in (
            ("Update", "Update this subscription now", self.update_requested, button_style),
            ("Rename", "Rename this subscription", self.rename_requested, button_style),
            ("Delete", "Delete this subscription and its profiles", self.delete_requested, delete_style),
        ):
            btn = QPushButton(label)
            btn.setFixedHeight(24)
            btn.setStyleSheet(style)
            btn.setToolTip(tip)
            btn.clicked.connect(lambda _checked=False, s=signal: s.emit(self.sub_id))
            top_row.addWidget(btn)
        outer.addLayout(top_row)

        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 0, 0, 0)
        bottom_row.setSpacing(8)

        status_bits = [f"{sub.profile_count} nodes"]
        if stats.expire_str:
            status_bits.append(f"till {stats.expire_str}")
        status = QLabel(" · ".join(status_bits))
        status.setStyleSheet("color: #8f95a3; font-size: 11px;")
        status.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bottom_row.addWidget(status, 1)

        if not stats.has_data:
            remaining_text = "No data"
            bar_tip = "No traffic info from provider"
            bar_value = 0
            chunk_color = "#3a4152"
        elif stats.unlimited:
            remaining_text = "∞ Unlimited"
            bar_tip = f"Used {format_bytes(stats.used)}, unlimited plan"
            bar_value = 100
            chunk_color = "#5aa86b"
        elif stats.over_quota:
            remaining_text = "Over quota"
            bar_tip = f"Used {format_bytes(stats.used)} of {format_bytes(stats.total)} — over quota"
            bar_value = 100
            chunk_color = "#e05252"
        else:
            assert stats.remaining is not None and stats.total is not None
            remaining_text = f"{format_bytes(stats.remaining)} left"
            bar_tip = f"Used {format_bytes(stats.used)} of {format_bytes(stats.total)}"
            bar_value = int(round(stats.percent))
            chunk_color = (
                "#e05252"
                if stats.percent >= 90
                else ("#e0a34e" if stats.percent >= 70 else "#5aa86b")
            )

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(bar_value)
        bar.setTextVisible(False)
        bar.setFixedWidth(140)
        bar.setFixedHeight(10)
        bar.setToolTip(bar_tip)
        bar.setStyleSheet(
            "QProgressBar { background: #121622; border: 1px solid #2d3340; border-radius: 5px; }"
            f"QProgressBar::chunk {{ background: {chunk_color}; border-radius: 4px; }}"
        )
        bottom_row.addWidget(bar)

        remaining = QLabel(remaining_text)
        remaining.setStyleSheet(
            "color: #ff8a8a; font-size: 11px; font-weight: 600;"
            if stats.over_quota
            else "color: #b9c0cf; font-size: 11px;"
        )
        remaining.setToolTip(bar_tip)
        bottom_row.addWidget(remaining)
        outer.addLayout(bottom_row)

        updated = (
            time.strftime("Updated: %Y-%m-%d %H:%M", time.localtime(sub.updated_at))
            if sub.updated_at > 0
            else ""
        )
        tip_lines = [
            sub.name,
            f"URL: {sub.original_link or sub.url}",
            f"Nodes: {sub.profile_count}",
            sub.userinfo_summary() or "No traffic info",
        ]
        if updated:
            tip_lines.append(updated)
        self.setToolTip("\n".join(tip_lines))

    def sizeHint(self) -> QSize:
        return QSize(400, 68)


class SubscriptionsDialog(QDialog):
    update_single_signal = Signal(str)
    update_all_signal = Signal()
    add_subscription_signal = Signal(str, str)
    delete_subscription_signal = Signal(str)

    def __init__(self, parent: MainWindow) -> None:
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Manage Subscriptions")
        self.resize(560, 480)
        self.setMinimumSize(460, 360)
        self._build_ui()
        self.refresh_list()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.header_label = QLabel("Active Subscriptions")
        self.header_label.setStyleSheet("font-size: 16px; font-weight: 700; color: #f0f1f5;")
        layout.addWidget(self.header_label)

        hint = QLabel("Subscriptions automatically synchronize and manage their VPN profiles.")
        hint.setStyleSheet("color: #8f95a3; font-size: 12px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.list_widget = QListWidget()
        self.list_widget.setStyleSheet(
            """
            QListWidget {
                background-color: #121622;
                border: 1px solid #2d3340;
                border-radius: 8px;
                padding: 6px;
            }
            QListWidget::item {
                background-color: #191e2b;
                border: 1px solid #2d3445;
                border-radius: 8px;
                margin-bottom: 6px;
                padding: 0px;
            }
            QListWidget::item:hover {
                background-color: #22293a;
                border: 1px solid #3d475f;
            }
            QListWidget::item:selected {
                background-color: #283147;
                border: 1px solid #f3b66a;
            }
            """
        )
        layout.addWidget(self.list_widget, 1)

        self.empty_label = QLabel(
            "No subscriptions yet.\nPaste a Happ link or HTTPS subscription URL via “Add subscription”."
        )
        self.empty_label.setStyleSheet("color: #8f95a3; font-size: 13px; padding: 24px;")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.empty_label.setVisible(False)
        layout.addWidget(self.empty_label, 1)

        # Buttons under list
        sub_actions_layout = QHBoxLayout()
        sub_actions_layout.setSpacing(8)

        self.update_btn = QPushButton("🔄 Update selected")
        self.update_btn.setStyleSheet("font-weight: 600; padding: 6px 12px;")
        self.update_btn.clicked.connect(self._on_update_selected)

        self.rename_btn = QPushButton("✏️ Rename")
        self.rename_btn.setStyleSheet("font-weight: 600; padding: 6px 12px;")
        self.rename_btn.clicked.connect(self._on_rename)

        self.delete_btn = QPushButton("🗑️ Delete")
        self.delete_btn.setStyleSheet("font-weight: 600; padding: 6px 12px; color: #ff8a8a;")
        self.delete_btn.clicked.connect(self._on_delete)

        sub_actions_layout.addWidget(self.update_btn)
        sub_actions_layout.addWidget(self.rename_btn)
        sub_actions_layout.addWidget(self.delete_btn)
        layout.addLayout(sub_actions_layout)

        # Bottom buttons
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(10)

        self.add_btn = QPushButton("➕ Add subscription")
        self.add_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #2d3a54;
                border: 1px solid #4a5c82;
                color: #ffffff;
                font-weight: 700;
                padding: 8px 16px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #3b4c6e;
            }
            """
        )
        self.add_btn.clicked.connect(self._on_add)

        self.update_all_btn = QPushButton("🔄 Update all")
        self.update_all_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #383020;
                border: 1px solid #6b5735;
                color: #f7ca88;
                font-weight: 700;
                padding: 8px 16px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #4a3f2b;
            }
            """
        )
        self.update_all_btn.clicked.connect(self._on_update_all)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("padding: 8px 16px; font-weight: 600;")
        close_btn.clicked.connect(self.accept)

        bottom_layout.addWidget(self.add_btn)
        bottom_layout.addWidget(self.update_all_btn)
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(close_btn)
        layout.addLayout(bottom_layout)

    def refresh_list(self) -> None:
        self.list_widget.clear()
        subs = self.main_window.subscription_store.all()
        total_nodes = sum(sub.profile_count for sub in subs)
        self.header_label.setText(f"Active Subscriptions ({len(subs)} · {total_nodes} nodes)")
        if not subs:
            self.list_widget.setVisible(False)
            self.empty_label.setVisible(True)
            self.update_btn.setEnabled(False)
            self.rename_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            self.update_all_btn.setEnabled(False)
            return

        self.list_widget.setVisible(True)
        self.empty_label.setVisible(False)
        self.update_btn.setEnabled(True)
        self.rename_btn.setEnabled(True)
        self.delete_btn.setEnabled(True)
        self.update_all_btn.setEnabled(True)

        for sub in subs:
            card = SubscriptionCard(sub)
            card.update_requested.connect(self._on_card_update)
            card.rename_requested.connect(self._on_card_rename)
            card.delete_requested.connect(self._on_card_delete)
            item = QListWidgetItem()
            item.setData(Qt.UserRole, sub.id)
            item.setSizeHint(card.sizeHint())
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, card)

        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

    def _select_sub_id(self, sub_id: str) -> None:
        for row in range(self.list_widget.count()):
            item = self.list_widget.item(row)
            if item is not None and item.data(Qt.UserRole) == sub_id:
                self.list_widget.setCurrentRow(row)
                return

    def _on_card_update(self, sub_id: str) -> None:
        self._select_sub_id(sub_id)
        self._on_update_selected()

    def _on_card_rename(self, sub_id: str) -> None:
        self._select_sub_id(sub_id)
        self._on_rename()

    def _on_card_delete(self, sub_id: str) -> None:
        self._select_sub_id(sub_id)
        self._on_delete()

    def _selected_sub_id(self) -> str | None:
        item = self.list_widget.currentItem()
        if not item:
            return None
        sub_id = item.data(Qt.UserRole)
        return str(sub_id) if sub_id else None

    def _on_update_selected(self) -> None:
        sub_id = self._selected_sub_id()
        if sub_id:
            self.update_single_signal.emit(sub_id)

    def _on_update_all(self) -> None:
        self.update_all_signal.emit()

    def _on_rename(self) -> None:
        sub_id = self._selected_sub_id()
        if not sub_id:
            return
        sub = self.main_window.subscription_store.get(sub_id)
        if not sub:
            return
        new_name, ok = QInputDialog.getText(self, "Rename subscription", "Subscription name:", text=sub.name)
        if ok and new_name.strip():
            sub.name = new_name.strip()
            self.main_window.subscription_store.put(sub)
            self.refresh_list()
            self.main_window._refresh_profile_views()

    def _on_delete(self) -> None:
        sub_id = self._selected_sub_id()
        if not sub_id:
            return
        sub = self.main_window.subscription_store.get(sub_id)
        if not sub:
            return
        res = QMessageBox.question(
            self,
            "Delete subscription",
            f'Delete subscription "{sub.name}" and remove all its profiles?',
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if res == QMessageBox.Yes:
            self.delete_subscription_signal.emit(sub_id)
            self.refresh_list()

    def _on_add(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Subscription")
        dialog.resize(440, 200)

        diag_layout = QVBoxLayout(dialog)
        diag_layout.setSpacing(10)

        lbl = QLabel("Enter Happ link or HTTPS subscription URL:")
        lbl.setStyleSheet("font-weight: 600;")
        diag_layout.addWidget(lbl)

        url_edit = QLineEdit()
        url_edit.setPlaceholderText("happ://add/https://... or https://example.com/sub?token=...")
        try:
            clip_text = QApplication.clipboard().text().strip()
        except RuntimeError:
            clip_text = ""
        if clip_text:
            clip_match = re.search(r"(happ://[^\s\"<>]+|https?://[^\s\"<>]+)", clip_text)
            if clip_match:
                url_edit.setText(clip_match.group(1).rstrip("\"';,.<>"))
        diag_layout.addWidget(url_edit)

        name_lbl = QLabel("Custom name (optional):")
        name_lbl.setStyleSheet("color: #8f95a3; font-size: 12px;")
        diag_layout.addWidget(name_lbl)

        name_edit = QLineEdit()
        name_edit.setPlaceholderText("My Provider")
        diag_layout.addWidget(name_edit)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        ok_btn = QPushButton("Add & Import")
        ok_btn.setStyleSheet("font-weight: 700; padding: 6px 14px;")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(ok_btn)
        diag_layout.addLayout(btn_row)

        def handle_ok():
            url = url_edit.text().strip()
            if not url:
                QMessageBox.warning(dialog, "Input error", "URL / Link cannot be empty")
                return
            dialog.accept()
            self.add_subscription_signal.emit(url, name_edit.text().strip())

        ok_btn.clicked.connect(handle_ok)
        dialog.exec()

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.subscriptions import Subscription, SubscriptionStore, format_bytes

if TYPE_CHECKING:
    from app.main_window import MainWindow


class SubscriptionsDialog(QDialog):
    update_single_signal = Signal(str)
    update_all_signal = Signal()
    add_subscription_signal = Signal(str, str)
    delete_subscription_signal = Signal(str)

    def __init__(self, parent: MainWindow) -> None:
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Manage Subscriptions")
        self.resize(500, 480)
        self.setMinimumSize(420, 360)
        self._build_ui()
        self.refresh_list()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QLabel("Active Subscriptions")
        header.setStyleSheet("font-size: 16px; font-weight: 700; color: #f0f1f5;")
        layout.addWidget(header)

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
                padding: 10px;
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
        if not subs:
            empty_item = QListWidgetItem("No subscriptions added yet. Click 'Add subscription' below.")
            empty_item.setFlags(Qt.NoItemFlags)
            self.list_widget.addItem(empty_item)
            self.update_btn.setEnabled(False)
            self.rename_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            self.update_all_btn.setEnabled(False)
            return

        self.update_btn.setEnabled(True)
        self.rename_btn.setEnabled(True)
        self.delete_btn.setEnabled(True)
        self.update_all_btn.setEnabled(True)

        for sub in subs:
            lines = [f"📌 {sub.name}  ({sub.profile_count} nodes)"]
            
            # Subtitle URL
            url_display = sub.original_link or sub.url
            if len(url_display) > 60:
                url_display = url_display[:57] + "..."
            lines.append(f"🔗 {url_display}")

            # Userinfo
            info_summary = sub.userinfo_summary()
            if info_summary:
                lines.append(f"📊 {info_summary}")

            # Updated timestamp
            if sub.updated_at > 0:
                updated_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(sub.updated_at))
                lines.append(f"🕒 Last updated: {updated_str}")
            else:
                lines.append("🕒 Never updated")

            item = QListWidgetItem("\n".join(lines))
            item.setData(Qt.UserRole, sub.id)
            item.setToolTip(f"{sub.name}\nURL: {sub.original_link or sub.url}\nNodes: {sub.profile_count}")
            self.list_widget.addItem(item)

        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

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

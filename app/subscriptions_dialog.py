"""Compact, in-window subscription management for ambox.

The panel manages subscription *sources*, never manual profile imports. A source's
nodes are opened in the separate Configs screen. Network requests remain in
MainWindow's bounded worker pool; this module only handles presentation.
"""
from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.subscriptions import Subscription, format_bytes, valid_subscription_link

if TYPE_CHECKING:
    from app.main_window import MainWindow


class AddSubscriptionDialog(QDialog):
    """Small explicit form. Prefilling from clipboard requires a button click."""

    def __init__(self, parent: QWidget, subscription: Subscription | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Изменить подписку" if subscription else "Добавить подписку")
        self.setMinimumWidth(350)
        self.resize(430, 215)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 16)
        layout.setSpacing(10)
        title = QLabel("Изменить ссылку" if subscription else "Новая подписка")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        hint = QLabel("Happ или URL подписки. Серверы появятся в разделе «Конфиги». ")
        hint.setObjectName("softHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        row = QHBoxLayout()
        self.url_edit = QLineEdit()
        self.url_edit.setObjectName("subscriptionUrl")
        self.url_edit.setPlaceholderText("https://provider.example/subscription/…")
        self.url_edit.setText((subscription.original_link or subscription.url) if subscription else "")
        self.url_edit.setToolTip("Ссылка может содержать токен доступа — не публикуйте её")
        row.addWidget(self.url_edit, 1)
        paste = QPushButton("Вставить")
        paste.clicked.connect(self._paste)
        row.addWidget(paste)
        layout.addLayout(row)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Название (необязательно)")
        self.name_edit.setText(subscription.name if subscription else "")
        if subscription:
            self.name_edit.hide()
        else:
            layout.addWidget(self.name_edit)
        self.error = QLabel("")
        self.error.setStyleSheet("color: #ff9999; font-size: 11px;")
        self.error.setWordWrap(True)
        self.error.hide()
        layout.addWidget(self.error)
        actions = QHBoxLayout()
        actions.addStretch(1)
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)
        self.submit_btn = QPushButton("Сохранить" if subscription else "Добавить")
        self.submit_btn.setObjectName("primaryAction")
        self.submit_btn.setDefault(True)
        self.submit_btn.clicked.connect(self._validate)
        actions.addWidget(self.submit_btn)
        layout.addLayout(actions)
        self.url_edit.returnPressed.connect(self._validate)
        self.url_edit.setFocus()

    def _paste(self) -> None:
        clipboard = QApplication.clipboard().text().strip()
        match = re.search(r"(happ://[^\s\"<>]+|https?://[^\s\"<>]+)", clipboard)
        if match:
            self.url_edit.setText(match.group(1).rstrip("\"';,.<>"))
        else:
            self.error.setText("Буфер обмена не содержит ссылку на подписку")
            self.error.show()

    def _validate(self) -> None:
        if not valid_subscription_link(self.url_edit.text()):
            self.error.setText("Введите корректную ссылку Happ, HTTPS или HTTP")
            self.error.show()
            self.url_edit.setFocus()
            return
        self.accept()

    @property
    def link(self) -> str:
        return self.url_edit.text().strip()

    @property
    def name(self) -> str:
        return self.name_edit.text().strip()


class SubscriptionCard(QFrame):
    """One source, one primary action and one overflow menu."""

    show_nodes = Signal(str)
    update_requested = Signal(str)
    rename_requested = Signal(str)
    link_requested = Signal(str)
    delete_requested = Signal(str)
    auto_update_changed = Signal(str, bool)

    def __init__(self, sub: Subscription, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.sub = sub
        self.setObjectName("subscriptionCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        body = QVBoxLayout(self)
        body.setContentsMargins(12, 11, 12, 11)
        body.setSpacing(7)

        top = QHBoxLayout()
        top.setSpacing(7)
        name = QLabel(sub.name)
        name.setObjectName("subscriptionName")
        name.setTextFormat(Qt.PlainText)
        name.setMinimumWidth(0)
        name.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        name.setToolTip(sub.name)
        top.addWidget(name, 1)
        count = QLabel(f"{sub.profile_count} серверов")
        count.setObjectName("softHint")
        top.addWidget(count)
        body.addLayout(top)

        stats = sub.traffic_stats()
        details = []
        if stats.has_data:
            if stats.unlimited:
                details.append("Безлимит" if stats.used <= 0 else f"Использовано {format_bytes(stats.used)}")
            elif stats.total is not None:
                details.append(f"Осталось {format_bytes(stats.remaining)} из {format_bytes(stats.total)}")
            if stats.expire_str:
                details.append(f"До {stats.expire_str}")
        if not details:
            details.append("Информация о трафике недоступна")
        summary = QLabel(" · ".join(details))
        summary.setObjectName("softHint")
        summary.setTextFormat(Qt.PlainText)
        summary.setWordWrap(True)
        body.addWidget(summary)
        if stats.has_data and not stats.unlimited:
            progress = QProgressBar()
            progress.setTextVisible(False)
            progress.setRange(0, 100)
            progress.setValue(round(stats.percent))
            progress.setFixedHeight(5)
            progress.setObjectName("subscriptionProgress")
            if stats.percent >= 90:
                progress.setProperty("quota", "critical")
            progress.setToolTip(f"Использовано {format_bytes(stats.used)}")
            body.addWidget(progress)

        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        self.activity = QLabel(self._last_updated())
        self.activity.setObjectName("softHint")
        self.activity.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bottom.addWidget(self.activity, 1)
        nodes_btn = QPushButton("Серверы")
        nodes_btn.setToolTip("Открыть серверы этой подписки")
        nodes_btn.clicked.connect(lambda: self.show_nodes.emit(sub.id))
        bottom.addWidget(nodes_btn)
        self.update_btn = QPushButton("Обновить")
        self.update_btn.clicked.connect(lambda: self.update_requested.emit(sub.id))
        bottom.addWidget(self.update_btn)
        more_btn = QPushButton("⋯")
        more_btn.setFixedWidth(30)
        more_btn.setToolTip("Дополнительные действия")
        more_btn.clicked.connect(lambda: self._show_menu(more_btn))
        bottom.addWidget(more_btn)
        body.addLayout(bottom)

    def _last_updated(self) -> str:
        if self.sub.updated_at <= 0:
            return "Ещё не обновлялась"
        return "Обновлено " + time.strftime("%d.%m %H:%M", time.localtime(self.sub.updated_at))

    def set_activity(self, message: str = "", *, busy: bool = False, error: bool = False) -> None:
        self.activity.setText(message or self._last_updated())
        self.activity.setStyleSheet("color: #ff9999;" if error else "")
        self.update_btn.setText("Обновление…" if busy else "Обновить")
        self.update_btn.setEnabled(not busy)

    def _show_menu(self, anchor: QPushButton) -> None:
        menu = QMenu(self)
        rename = menu.addAction("Переименовать")
        edit = menu.addAction("Изменить ссылку")
        auto = menu.addAction("Автообновление")
        auto.setCheckable(True)
        auto.setChecked(self.sub.auto_update)
        menu.addSeparator()
        delete = menu.addAction("Удалить подписку…")
        chosen = menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))
        if chosen is rename:
            self.rename_requested.emit(self.sub.id)
        elif chosen is edit:
            self.link_requested.emit(self.sub.id)
        elif chosen is auto:
            self.auto_update_changed.emit(self.sub.id, auto.isChecked())
        elif chosen is delete:
            self.delete_requested.emit(self.sub.id)


class SubscriptionsPanel(QWidget):
    """An always-visible page, not a modal nested under a second window."""

    update_single_signal = Signal(str)
    update_all_signal = Signal()
    add_subscription_signal = Signal(str, str)
    edit_subscription_link_signal = Signal(str, str)
    delete_subscription_signal = Signal(str)
    nodes_requested = Signal(str)

    def __init__(self, parent: MainWindow) -> None:
        super().__init__(parent)
        self.main_window = parent
        self._cards: dict[str, SubscriptionCard] = {}
        self._states: dict[str, tuple[str, bool, bool]] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        head = QHBoxLayout()
        title = QLabel("Подписки")
        title.setObjectName("sectionTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.add_btn = QPushButton("+ Добавить")
        self.add_btn.setObjectName("primaryAction")
        self.add_btn.clicked.connect(self.open_add_dialog)
        head.addWidget(self.add_btn)
        root.addLayout(head)
        tip = QLabel("Добавляйте и обновляйте источники здесь. Их серверы отдельно находятся в «Конфигах».")
        tip.setObjectName("softHint")
        tip.setWordWrap(True)
        root.addWidget(tip)
        self.feedback = QLabel("")
        self.feedback.setObjectName("softHint")
        self.feedback.setWordWrap(True)
        self.feedback.hide()
        root.addWidget(self.feedback)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        self.cards_layout = QVBoxLayout(host)
        self.cards_layout.setContentsMargins(0, 2, 0, 2)
        self.cards_layout.setSpacing(9)
        self.empty = QLabel("Подписок пока нет.\nНажмите «Добавить», чтобы импортировать первую.")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setObjectName("emptyState")
        self.empty.setWordWrap(True)
        self.cards_layout.addWidget(self.empty)
        self.cards_layout.addStretch(1)
        self.scroll.setWidget(host)
        root.addWidget(self.scroll, 1)
        foot = QHBoxLayout()
        self.counter = QLabel("0 подписок")
        self.counter.setObjectName("softHint")
        foot.addWidget(self.counter, 1)
        self.refresh_btn = QPushButton("Обновить все")
        self.refresh_btn.clicked.connect(lambda: self.update_all_signal.emit())
        foot.addWidget(self.refresh_btn)
        root.addLayout(foot)
        self.refresh_list()

    def set_feedback(self, message: str, *, error: bool = False) -> None:
        self.feedback.setText(message)
        self.feedback.setStyleSheet("color: #ff9999;" if error else "")
        self.feedback.setVisible(bool(message))

    def set_update_state(self, sub_id: str, message: str = "", *, busy: bool = False, error: bool = False) -> None:
        if message:
            self._states[sub_id] = (message, busy, error)
        else:
            self._states.pop(sub_id, None)
        card = self._cards.get(sub_id)
        if card:
            card.set_activity(message, busy=busy, error=error)

    def refresh_list(self) -> None:
        subs = self.main_window.subscription_store.all()
        for card in self._cards.values():
            self.cards_layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()
        self.empty.setVisible(not subs)
        self.refresh_btn.setEnabled(bool(subs))
        self.counter.setText(f"{len(subs)} подписок")
        for index, sub in enumerate(subs):
            card = SubscriptionCard(sub, self)
            card.show_nodes.connect(self.nodes_requested)
            card.update_requested.connect(self._on_update)
            card.rename_requested.connect(self._on_rename)
            card.link_requested.connect(self._on_edit_link)
            card.delete_requested.connect(self._on_delete)
            card.auto_update_changed.connect(self._on_auto_update)
            self.cards_layout.insertWidget(index, card)
            self._cards[sub.id] = card
            state = self._states.get(sub.id)
            if state:
                card.set_activity(state[0], busy=state[1], error=state[2])
        for sub_id in list(self._states):
            if not any(sub.id == sub_id for sub in subs):
                self._states.pop(sub_id, None)

    def open_add_dialog(self) -> None:
        dialog = AddSubscriptionDialog(self)
        if dialog.exec() == QDialog.Accepted:
            self.set_feedback("Добавление подписки…")
            self.add_subscription_signal.emit(dialog.link, dialog.name)

    def _on_update(self, sub_id: str) -> None:
        self.update_single_signal.emit(sub_id)

    def _on_rename(self, sub_id: str) -> None:
        sub = self.main_window.subscription_store.get(sub_id)
        if not sub:
            return
        name, ok = QInputDialog.getText(self, "Переименовать", "Название подписки:", text=sub.name)
        if ok and name.strip():
            sub.name = name.strip()
            self.main_window.subscription_store.put(sub)
            self.refresh_list()
            self.main_window._refresh_profile_views()

    def _on_edit_link(self, sub_id: str) -> None:
        sub = self.main_window.subscription_store.get(sub_id)
        if not sub:
            return
        dialog = AddSubscriptionDialog(self, subscription=sub)
        if dialog.exec() == QDialog.Accepted and dialog.link != (sub.original_link or sub.url):
            self.edit_subscription_link_signal.emit(sub_id, dialog.link)

    def _on_auto_update(self, sub_id: str, enabled: bool) -> None:
        sub = self.main_window.subscription_store.get(sub_id)
        if sub:
            sub.auto_update = enabled
            self.main_window.subscription_store.put(sub)
            self.refresh_list()

    def _on_delete(self, sub_id: str) -> None:
        sub = self.main_window.subscription_store.get(sub_id)
        if not sub:
            return
        answer = QMessageBox.question(
            self, "Удаление подписки",
            f"Удалить «{sub.name}» и {sub.profile_count} её серверов?\n"
            "Конфиги, добавленные вручную, не будут затронуты.",
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel,
        )
        if answer == QMessageBox.Yes:
            self.delete_subscription_signal.emit(sub_id)
            self.refresh_list()

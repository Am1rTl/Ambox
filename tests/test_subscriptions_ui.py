"""Offscreen Qt smoke tests for the compact subscription UI.

Runs on CI with PySide6. Skips cleanly in minimal/headless Python environments
where the optional GUI dependency is not installed.
"""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QDialog, QWidget  # noqa: E402

from app.subscriptions import Subscription  # noqa: E402
from app.subscriptions_dialog import (  # noqa: E402
    AddSubscriptionDialog,
    SubscriptionCard,
    SubscriptionsPanel,
)


@pytest.fixture(scope="module")
def app():
    existing = QApplication.instance()
    instance = existing or QApplication([])
    yield instance
    if not existing:
        instance.quit()


class FakeStore:
    def __init__(self, subscriptions=None):
        self.data = {s.id: s for s in subscriptions or []}

    def all(self):
        return list(self.data.values())

    def get(self, sub_id):
        return self.data.get(sub_id)

    def put(self, sub):
        self.data[sub.id] = sub


class FakeWindow(QWidget):
    def __init__(self, subscriptions=None):
        super().__init__()
        self.subscription_store = FakeStore(subscriptions)
        self.refreshed = False

    def _refresh_profile_views(self):
        self.refreshed = True


def test_embedded_subscription_page_has_empty_state_and_add_action(app):
    parent = FakeWindow()
    panel = SubscriptionsPanel(parent)
    assert not panel.empty.isHidden()
    assert panel.refresh_btn.isEnabled() is False
    assert panel.add_btn.text() == "+ Добавить"
    assert len(panel._cards) == 0
    panel.close()
    parent.close()


def test_subscription_cards_show_nodes_and_update_status(app):
    source = Subscription(id="source-a", name="Example Provider", url="https://example.org/sub",
                          profile_count=3, updated_at=1700000000,
                          user_info={"upload": 100, "download": 150, "total": 1000})
    parent = FakeWindow([source])
    panel = SubscriptionsPanel(parent)
    card = panel._cards["source-a"]
    assert isinstance(card, SubscriptionCard)
    assert panel.refresh_btn.isEnabled() is True
    seen = []
    panel.nodes_requested.connect(seen.append)
    card.show_nodes.emit("source-a")
    assert seen == ["source-a"]
    panel.set_update_state("source-a", "Обновление…", busy=True)
    assert card.update_btn.isEnabled() is False
    panel.set_update_state("source-a", "Готово · 3 серверов")
    assert card.update_btn.isEnabled() is True
    assert "Готово" in card.activity.text()
    panel.close()
    parent.close()


def test_add_subscription_dialog_rejects_config_links(app):
    parent = QWidget()
    dialog = AddSubscriptionDialog(parent)
    dialog.url_edit.setText("vless://credentials@host:443")
    dialog._validate()
    assert dialog.error.isHidden() is False
    dialog.url_edit.setText("https://example.org/sub?token=secret")
    dialog._validate()
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.close()
    parent.close()

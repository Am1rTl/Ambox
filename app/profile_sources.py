"""Pure source ownership filters shared by the UI and regression tests.

An imported config is owned by the user; a subscription node is owned by its
subscription, and should not appear in the manual list or be silently edited.
"""
from __future__ import annotations

from typing import Protocol


class ProfileWithSource(Protocol):
    subscription_id: str | None


def profile_indices_for_source(
    profiles: list[ProfileWithSource], source: str, subscription_id: str = ""
) -> list[int]:
    """Return indices without changing storage order or profile identity."""
    if source == "manual":
        return [index for index, p in enumerate(profiles) if not p.subscription_id]
    if source == "subscriptions":
        return [index for index, p in enumerate(profiles)
                if p.subscription_id and (not subscription_id or p.subscription_id == subscription_id)]
    raise ValueError(f"Unknown profile source: {source}")

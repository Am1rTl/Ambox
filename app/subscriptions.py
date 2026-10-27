from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlparse

from app.app_paths import ensure_user_owned, subscriptions_path
from app.config_parser import ConfigError, Profile, load_profiles_from_text
from app.happ_links import (
    HappLinkError,
    fetch_subscription_with_info,
    is_happ_link,
    unwrap_happ_link,
)


def _coerce_number(value: Any, default: float = 0) -> int | float:
    """Best-effort number coercion for values loaded from JSON or headers."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return default
    return default


@dataclass
class Subscription:
    id: str
    name: str
    url: str
    original_link: str = ""
    updated_at: float = 0.0
    profile_count: int = 0
    auto_update: bool = True
    user_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Subscription:
        user_info = data.get("user_info")
        return cls(
            id=str(data.get("id") or ""),
            name=str(data.get("name") or "Subscription"),
            url=str(data.get("url") or ""),
            original_link=str(data.get("original_link") or ""),
            updated_at=float(_coerce_number(data.get("updated_at"), 0.0)),
            profile_count=int(_coerce_number(data.get("profile_count"), 0)),
            auto_update=bool(data.get("auto_update", True)),
            user_info=dict(user_info) if isinstance(user_info, dict) else {},
        )

    def traffic_stats(self) -> TrafficStats:
        """Used/limit/remaining/percent/expiry derived from user_info.

        Handles missing (None/absent), zero, negative and string values:
        a missing or non-positive total means an unlimited plan.
        ``has_data`` is False when the provider sent no user_info at all,
        which callers must render as "no data", not "unlimited".
        """
        info = self.user_info if isinstance(self.user_info, dict) else {}
        upload = max(0.0, float(_coerce_number(info.get("upload"), 0)))
        download = max(0.0, float(_coerce_number(info.get("download"), 0)))
        total_raw = float(_coerce_number(info.get("total"), 0))
        expire = max(0.0, float(_coerce_number(info.get("expire"), 0)))

        used = upload + download
        unlimited = total_raw <= 0
        total = total_raw if not unlimited else None
        if unlimited:
            remaining: float | None = None
            percent = 0.0
            over_quota = False
        else:
            remaining = max(0.0, total_raw - used)
            percent = min(100.0, (used / total_raw * 100.0) if total_raw > 0 else 0.0)
            over_quota = used > total_raw
        expire_str = time.strftime("%Y-%m-%d", time.localtime(expire)) if expire > 0 else ""
        return TrafficStats(
            used=used,
            total=total,
            remaining=remaining,
            percent=percent,
            unlimited=unlimited,
            over_quota=over_quota,
            expire=expire,
            expire_str=expire_str,
            has_data=bool(info),
        )

    def userinfo_summary(self) -> str:
        if not self.user_info:
            return ""
        stats = self.traffic_stats()
        parts: list[str] = []
        if stats.unlimited:
            if stats.used > 0:
                parts.append(f"Used: {format_bytes(stats.used)} (unlimited)")
        else:
            assert stats.total is not None
            text = f"Traffic: {format_bytes(stats.used)} / {format_bytes(stats.total)}"
            if stats.over_quota:
                text += " (over quota)"
            parts.append(text)

        if stats.expire_str:
            parts.append(f"Expires: {stats.expire_str}")

        return " | ".join(parts)


@dataclass(frozen=True)
class TrafficStats:
    used: float
    total: float | None  # None = unlimited plan
    remaining: float | None  # None = unlimited plan
    percent: float  # 0..100, clamped
    unlimited: bool
    over_quota: bool
    expire: float  # 0 = no expiry info
    expire_str: str  # "" = no expiry info
    has_data: bool  # False = provider sent no user_info; not "unlimited"


def format_bytes(value: Any) -> str:
    if value is None:
        return "—"
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "—"
    if number != number:  # NaN
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = max(0.0, number)
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.1f} {unit}"


def generate_subscription_id(url: str) -> str:
    cleaned = url.strip().lower()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]


def derive_subscription_name(url: str, headers_info: dict[str, Any] | None = None) -> str:
    if headers_info:
        title = headers_info.get("profile_title")
        if title:
            if title.lower().startswith("base64:"):
                import base64
                try:
                    decoded = base64.b64decode(title[7:].strip()).decode("utf-8").strip()
                    if decoded:
                        return decoded
                except Exception:
                    pass
            return title
        filename = headers_info.get("filename")
        if filename:
            name = Path(filename).stem
            if name:
                return name

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host:
        return f"Sub ({host})"
    return "Subscription"


def is_likely_subscription_url(value: str) -> bool:
    s = value.strip()
    if is_happ_link(s):
        return True
    try:
        parsed = urlparse(s)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False
        # If it has userinfo like http://user:pass@host:port, it is an explicit HTTP proxy, not a sub
        if parsed.username or parsed.password:
            return False
        # If it has no path (or just /), no query, but has an explicit port (e.g. http://1.2.3.4:8080), it is a proxy
        if (not parsed.path or parsed.path == "/") and not parsed.query and parsed.port:
            return False
        # Any http/https URL with a path or query is treated as a subscription / config URL
        if (parsed.path and parsed.path != "/") or parsed.query:
            return True
        return False
    except Exception:
        return False


def fetch_subscription_profiles(
    url_or_link: str,
    fetcher: Callable[[str], tuple[str, dict[str, Any]]] | None = None,
) -> tuple[list[Profile], str, dict[str, Any]]:
    link = url_or_link.strip()
    original_target = link
    if is_happ_link(link):
        try:
            target = unwrap_happ_link(link)
        except HappLinkError as exc:
            raise ConfigError(str(exc)) from exc
    else:
        target = link

    parsed = urlparse(target)
    if parsed.scheme.lower() not in {"http", "https"}:
        profiles = load_profiles_from_text(target)
        return profiles, target, {}

    actual_fetcher = fetcher or fetch_subscription_with_info
    try:
        content, headers_info = actual_fetcher(target)
    except Exception as exc:
        raise ConfigError(f"Failed to fetch subscription: {exc}") from exc

    try:
        profiles = load_profiles_from_text(content)
    except ConfigError as exc:
        # Check if base64 encoded
        from app.config_parser import _decode_base64_text

        try:
            decoded = _decode_base64_text(content.strip(), "subscription")
            profiles = load_profiles_from_text(decoded)
        except Exception:
            raise exc

    return profiles, target, headers_info


class SubscriptionStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or subscriptions_path()
        self.subscriptions: dict[str, Subscription] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError):
            self.subscriptions = {}
            return
        items: list[Any]
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict) and isinstance(data.get("subscriptions"), list):
            items = data["subscriptions"]
        else:
            self.subscriptions = {}
            return
        # One corrupt entry must not wipe the whole store: skip bad items.
        subs: dict[str, Subscription] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                sub = Subscription.from_dict(item)
            except (TypeError, ValueError):
                continue
            if sub.id:
                subs[sub.id] = sub
        self.subscriptions = subs

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"subscriptions": [sub.to_dict() for sub in self.subscriptions.values()]}
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        ensure_user_owned(tmp_path)
        if self.path.exists():
            backup_path = self.path.with_suffix(self.path.suffix + ".bak")
            try:
                shutil.copy2(self.path, backup_path)
                ensure_user_owned(backup_path)
            except OSError:
                pass
        tmp_path.replace(self.path)
        ensure_user_owned(self.path)

    def get(self, sub_id: str) -> Subscription | None:
        return self.subscriptions.get(sub_id)

    def all(self) -> list[Subscription]:
        return sorted(self.subscriptions.values(), key=lambda s: s.name.lower())

    def put(self, sub: Subscription) -> None:
        self.subscriptions[sub.id] = sub
        self.save()

    def remove(self, sub_id: str) -> None:
        if sub_id in self.subscriptions:
            del self.subscriptions[sub_id]
            self.save()

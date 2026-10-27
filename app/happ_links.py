from __future__ import annotations

import base64
import binascii
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

from app.happ_crypto import HappCryptoError, decrypt_happ_payload

MAX_SUBSCRIPTION_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 20
_LINK_PREFIX = "happ://"
_ALLOWED_ACTIONS = {"add", "import", "sub", "subscribe", "subscription", "install"}
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


class HappLinkError(ValueError):
    pass


def is_happ_link(value: str) -> bool:
    return value.strip().lower().startswith(_LINK_PREFIX)


def _looks_like_link(value: str) -> bool:
    return bool(_SCHEME_RE.match(value.strip()))


def _decode_base64_link(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 8:
        return None
    try:
        padded = compact + "=" * ((4 - len(compact) % 4) % 4)
        decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        text = decoded.decode("utf-8").strip()
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError, binascii.Error):
        return None
    return text if _looks_like_link(text) else None


def _query_payload(parsed) -> str:
    values = parse_qs(parsed.query)
    for key in ("url", "link", "payload"):
        candidates = values.get(key)
        if candidates and candidates[0].strip():
            return candidates[0].strip()
    return ""


def unwrap_happ_link(value: str) -> str:
    current = value.strip()
    if not current:
        raise HappLinkError("empty Happ link")

    for _ in range(8):
        if not current.lower().startswith(_LINK_PREFIX):
            return current

        # Handle direct happ://https://... or happ://http://...
        prefix_len = len(_LINK_PREFIX)
        remainder = current[prefix_len:].strip()
        if remainder.startswith("https://") or remainder.startswith("http://"):
            current = remainder
            continue
        if remainder.startswith("https:/") and not remainder.startswith("https://"):
            current = "https://" + remainder[7:].lstrip("/")
            continue
        if remainder.startswith("http:/") and not remainder.startswith("http://"):
            current = "http://" + remainder[6:].lstrip("/")
            continue

        parsed = urlparse(current)
        action = parsed.netloc.lower()
        if not action:
            # Maybe path contains action or url, e.g. happ:///https://...
            path_part = parsed.path.lstrip("/")
            if path_part.startswith("https://") or path_part.startswith("http://"):
                current = path_part
                continue
            raise HappLinkError("Happ link is missing an action")

        raw_tail = current[len(_LINK_PREFIX) :]
        _, separator, raw_payload = raw_tail.partition("/")
        payload = raw_payload.lstrip("/") if separator else ""
        if not payload or payload.startswith("?"):
            payload = _query_payload(parsed) or payload
        payload = unquote(payload).strip()

        if action.startswith("crypt"):
            if not payload:
                raise HappLinkError("Happ crypt link has an empty payload")
            try:
                decrypted = decrypt_happ_payload(action, payload)
            except HappCryptoError as exc:
                raise HappLinkError(f"failed to decrypt encrypted Happ link ({action}): {exc}") from exc
            current = decrypted.strip()
            continue

        if action not in _ALLOWED_ACTIONS:
            # Check if netloc itself is a domain name for an http/https URL, e.g. happ://example.com/sub
            if "." in action:
                current = f"https://{raw_tail}"
                continue
            raise HappLinkError(f"unsupported Happ action: {action}")

        if not payload:
            raise HappLinkError("Happ link has an empty payload")

        decoded = _decode_base64_link(payload)
        if decoded:
            payload = decoded
        if payload == current:
            raise HappLinkError("Happ link points to itself")
        current = payload

    raise HappLinkError("too many nested Happ links")


_SIZE_SUFFIXES = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "t": 1024**4,
    "tb": 1024**4,
}


def _parse_userinfo_number(value: str) -> int | None:
    """Parse ints, floats and size-suffixed values (e.g. '10GB', '1.5 mb')."""
    text = value.strip().lower().replace(" ", "")
    if not text:
        return None
    match = re.match(r"^([+-]?\d+(?:\.\d+)?)([a-z]*)$", text)
    if not match:
        return None
    number, suffix = match.groups()
    if suffix not in _SIZE_SUFFIXES:
        return None
    try:
        return int(float(number) * _SIZE_SUFFIXES[suffix])
    except ValueError:
        return None


def parse_subscription_userinfo(header_value: str) -> dict[str, int]:
    result: dict[str, int] = {}
    if not header_value:
        return result
    for part in header_value.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if not k:
                continue
            number = _parse_userinfo_number(v)
            if number is not None:
                result[k] = number
    return result


def fetch_subscription_with_info(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> tuple[str, dict[str, Any]]:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise HappLinkError("subscription target must be an HTTP(S) URL")

    request = Request(
        url,
        headers={
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "identity",
            "User-Agent": "Happ/1.0.0 (Linux; Ambox/1.0) v2rayN/6.23 sing-box/1.8.0",
        },
    )
    headers_dict: dict[str, Any] = {}
    try:
        with urlopen(request, timeout=timeout) as response:
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_SUBSCRIPTION_BYTES:
                        raise HappLinkError("subscription response is too large")
                except ValueError:
                    pass

            userinfo_raw = response.headers.get("Subscription-Userinfo") or response.headers.get("subscription-userinfo")
            if userinfo_raw:
                headers_dict["user_info"] = parse_subscription_userinfo(userinfo_raw)

            profile_title = response.headers.get("Profile-Title") or response.headers.get("profile-title")
            if profile_title:
                headers_dict["profile_title"] = unquote(profile_title).strip()

            update_interval = response.headers.get("Profile-Update-Interval") or response.headers.get("profile-update-interval")
            if update_interval and update_interval.isdigit():
                headers_dict["update_interval_hours"] = int(update_interval)

            disposition = response.headers.get("Content-Disposition") or response.headers.get("content-disposition")
            if disposition and "filename" in disposition.lower():
                match = re.search(r"filename\*?=['\"]?(?:UTF-\d['\"])?([^;\"]+)", disposition, re.I)
                if match:
                    headers_dict["filename"] = unquote(match.group(1)).strip()

            data = response.read(MAX_SUBSCRIPTION_BYTES + 1)
    except HappLinkError:
        raise
    except HTTPError as exc:
        raise HappLinkError(f"subscription request failed with HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise HappLinkError(f"subscription request failed: {exc}") from exc

    if len(data) > MAX_SUBSCRIPTION_BYTES:
        raise HappLinkError("subscription response is too large")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HappLinkError("subscription response is not UTF-8 text") from exc

    return text, headers_dict


def fetch_subscription(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> str:
    text, _ = fetch_subscription_with_info(url, timeout=timeout)
    return text

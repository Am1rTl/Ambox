"""Small, dependency-free privacy helpers used for local config and support logs.

The VPN configuration necessarily contains credentials; the on-disk files are
private, and diagnostics/logs must not copy them into less protected places.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

_SECRET_KEY = re.compile(r"(?:password|passwd|token|secret|authorization|private[_-]?key|uuid|access[_-]?key|api[_-]?key|auth)", re.I)
_PRIVATE_LINK = re.compile(r"(?i)\b(?:vless|vmess|trojan|ss|hysteria2|hy2|happ)://[^\s<>\"']+")
_QUERY_SECRET = re.compile(r"(?i)([?&](?:token|key|password|secret|auth|access_token|uuid)=)[^&#\s]+")
_FIELD_SECRET = re.compile(r"(?i)(\b(?:password|token|secret|uuid|authorization|private_key)\b\s*[:=]\s*['\"]?)[^\s,'\"}]+")
_JSON_FIELD_SECRET = re.compile(r'(?i)("(?:password|passwd|token|secret|uuid|authorization|private_key|api_key)"\s*:\s*")[^"]*')
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def redact(text: str) -> str:
    """Best effort for display/export (never a guarantee for arbitrary binary logs)."""
    result = _PRIVATE_LINK.sub(lambda m: m.group(0).split('://', 1)[0] + '://[redacted]', str(text))
    result = _QUERY_SECRET.sub(r'\1[redacted]', result)
    result = _FIELD_SECRET.sub(r'\1[redacted]', result)
    result = _JSON_FIELD_SECRET.sub(r'\1[redacted]', result)
    return _UUID.sub('[redacted-uuid]', result)


def redacted_structure(value: Any) -> Any:
    """Remove known credentials from structured diagnostics before export."""
    if isinstance(value, dict):
        return {str(k): ('[redacted]' if _SECRET_KEY.search(str(k)) else redacted_structure(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redacted_structure(x) for x in value]
    if isinstance(value, str):
        return redact(value)
    return value


def atomic_private_write(path: Path, contents: str) -> None:
    """Atomic replacement, with 0600 permissions even under a permissive umask.

    The temporary file is created inside the target directory to keep rename
    atomic. On failure the original file remains untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name: str | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
        if os.name == 'posix':
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as writer:
            writer.write(contents)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
        if os.name == 'posix':
            path.chmod(0o600)
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def atomic_private_json(path: Path, payload: Any) -> None:
    atomic_private_write(path, json.dumps(payload, indent=2, ensure_ascii=False))

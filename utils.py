"""Shared utility helpers for FETIH.

Cross-cutting concerns: URL matching, env-var booleans, atomic file writes.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def base_url_hostname(base_url: str) -> str:
    """Return the hostname (no port) from a base URL string."""
    if not base_url:
        return ""
    try:
        return urlparse(base_url).hostname or ""
    except Exception:
        return ""


def base_url_host_matches(base_url: str, hostname: str) -> bool:
    """Return True when *base_url*'s host equals or ends with *hostname*."""
    if not base_url or not hostname:
        return False
    host = base_url_hostname(base_url)
    return host == hostname or host.endswith(f".{hostname}")


def normalize_proxy_url(url: str) -> str:
    """Normalize a proxy URL to include a scheme if missing."""
    if not url:
        return url
    if "://" not in url:
        return f"http://{url}"
    return url


def normalize_proxy_env_vars() -> None:
    """Ensure HTTPS_PROXY / HTTP_PROXY env vars have a scheme prefix."""
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        val = os.environ.get(var)
        if val:
            os.environ[var] = normalize_proxy_url(val)


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def is_truthy_value(value: Any) -> bool:
    """Return True for truthy string/bool/int values."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def env_var_enabled(name: str, default: bool = False) -> bool:
    """Return True when an env var is set to a truthy value."""
    val = os.environ.get(name)
    if val is None:
        return default
    return is_truthy_value(val)


# ---------------------------------------------------------------------------
# JSON / file helpers
# ---------------------------------------------------------------------------

def safe_json_loads(text: str, default: Any = None) -> Any:
    """Try to parse JSON; return *default* on any error."""
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def atomic_json_write(path: str | Path, data: Any, *, indent: int = 2) -> None:
    """Write JSON data atomically (write to tmp, then rename)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_replace(path: str | Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write *content* to *path* atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

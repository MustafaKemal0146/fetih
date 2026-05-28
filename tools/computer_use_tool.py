"""Shim for tool discovery. Registers `computer_use` with tools.registry.

The real implementation lives in the `tools/computer_use/` package to keep
the file structure clean. This shim exists because tools.registry auto-imports
`tools/*.py` — we need a top-level module to trigger the registration.

SAFETY: computer_use is DISABLED by default. The user must explicitly run
`/computer-use on` to enable it. This prevents accidental desktop control
in headless/server environments.
"""

from __future__ import annotations

import os

from tools.computer_use.schema import COMPUTER_USE_SCHEMA
from tools.computer_use.tool import (
    check_computer_use_requirements,
    handle_computer_use,
    set_approval_callback,
)
from tools.registry import registry


def _is_desktop_enabled() -> bool:
    """Check if user has explicitly enabled desktop control AND backend is available."""
    enabled = os.environ.get("FETIH_DESKTOP_ENABLED", "").strip() in ("1", "true", "yes", "on")
    if not enabled:
        return False
    return check_computer_use_requirements()


def enable_desktop() -> bool:
    """Enable desktop control for this session. Returns True if backend is available."""
    backend_ok = check_computer_use_requirements()
    if backend_ok:
        os.environ["FETIH_DESKTOP_ENABLED"] = "1"
    return backend_ok


def disable_desktop() -> None:
    """Disable desktop control for this session."""
    os.environ.pop("FETIH_DESKTOP_ENABLED", None)


def is_desktop_enabled() -> bool:
    """Check if desktop control is currently enabled."""
    return os.environ.get("FETIH_DESKTOP_ENABLED", "").strip() in ("1", "true", "yes", "on")


_PLATFORM = __import__('sys').platform
if _PLATFORM == "darwin":
    _BACKEND_DESC = "macOS masaüstü kontrolü (cua-driver ile arka planda, fareyi çalmaz)"
else:
    _BACKEND_DESC = f"{'Linux' if _PLATFORM == 'linux' else 'Windows'} masaüstü kontrolü (pyautogui ile — farenizi hareket ettirir, ekranınızı kullanır)"


registry.register(
    name="computer_use",
    toolset="computer_use",
    schema=COMPUTER_USE_SCHEMA,
    handler=lambda args, **kw: handle_computer_use(args, **kw),
    check_fn=_is_desktop_enabled,
    requires_env=["FETIH_DESKTOP_ENABLED"],
    description=(
        f"{_BACKEND_DESC}. "
        "KULLANIM: /computer-use on ile aktif et. "
        "Aksiyonlar: capture (ekran goruntusu), click, type, key, scroll, drag, "
        "wait, list_apps, focus_app. "
        "GUVENLIK: FAILSAFE aktif (mouse sol ust koseye cekilirse durur). "
        "Tum aksiyonlar ~/.fetih/desktop_audit.log dosyasina kaydedilir."
    ),
)


__all__ = [
    "handle_computer_use",
    "set_approval_callback",
    "check_computer_use_requirements",
    "enable_desktop",
    "disable_desktop",
    "is_desktop_enabled",
]

"""computer_use_tool — global enable/disable switch + public API.

This module is imported by ``cli.py`` for the ``/computer-use`` command.
It wraps the registry-based tool with a simple on/off flag that the
approval callback and system prompt can interrogate.
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_desktop_enabled = False
_approval_callback = None


# ---------------------------------------------------------------------------
# Public API used by cli.py
# ---------------------------------------------------------------------------

def enable_desktop() -> bool:
    """Enable desktop control. Returns True on success."""
    global _desktop_enabled
    with _lock:
        # Trigger tool module import so it self-registers
        try:
            import tools.computer_use.tool  # noqa: F401
        except Exception as exc:
            logger.warning("computer_use tool import failed: %s", exc)
            return False
        _desktop_enabled = True
        return True


def disable_desktop() -> None:
    """Disable desktop control."""
    global _desktop_enabled
    with _lock:
        _desktop_enabled = False


def is_desktop_enabled() -> bool:
    """Return True when desktop control is currently active."""
    return _desktop_enabled


def set_approval_callback(cb) -> None:
    """Wire up the CLI approval dialog for computer_use actions."""
    global _approval_callback
    _approval_callback = cb
    try:
        from tools.computer_use.tool import set_approval_callback as _set
        _set(cb)
    except Exception:
        pass

"""computer_use tool — self-registers with the tool registry.

Imported by ``discover_builtin_tools()`` and by ``tools/computer_use_tool.py``.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, Optional

from tools.registry import registry, tool_error
from tools.computer_use.schema import COMPUTER_USE_SCHEMA
from fetih_cli.desktop_safety import (
    validate_desktop_action,
    log_desktop_action,
    format_approval_prompt,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Approval callback (set by CLI before first use)
# ---------------------------------------------------------------------------

_approval_callback = None   # callable(action, args, summary) -> verdict str


def set_approval_callback(cb) -> None:
    global _approval_callback
    _approval_callback = cb


def _request_approval(action: str, args: Dict) -> str:
    """Ask for user approval; return 'approved' or 'denied'."""
    if _approval_callback is None:
        return "approved"   # Non-interactive — auto-approve
    summary = format_approval_prompt(action, args)
    try:
        verdict = _approval_callback(action, args, summary)
        if verdict in {"approve_once", "approve_session", "always_approve"}:
            return "approved"
        return "denied"
    except Exception:
        return "denied"


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def _handle_computer_use(
    action: str,
    coordinate: Optional[list] = None,
    text: Optional[str] = None,
    keys: Optional[str] = None,
    direction: Optional[str] = None,
    amount: int = 3,
    from_coordinate: Optional[list] = None,
    to_coordinate: Optional[list] = None,
    duration: float = 0.2,
    interval: float = 0.0,
    **_extra: Any,
) -> str:
    """Execute a desktop action and return a JSON result string."""
    from tools.computer_use_tool import is_desktop_enabled

    if not is_desktop_enabled():
        return tool_error(
            "Desktop control is disabled. Run '/computer-use on' to enable it."
        )

    args = {
        "coordinate": coordinate,
        "text": text,
        "keys": keys,
        "direction": direction,
        "amount": amount,
        "from_coordinate": from_coordinate,
        "to_coordinate": to_coordinate,
        "duration": duration,
    }

    # Safety validation
    allowed, err_msg = validate_desktop_action(action, args)
    if not allowed:
        return tool_error(err_msg or f"Action '{action}' blocked by safety layer")

    # Approval for tier ≥2 actions
    from fetih_cli.desktop_safety import get_safety_tier, requires_approval
    if requires_approval(action, approval_level=2):
        verdict = _request_approval(action, args)
        if verdict != "approved":
            log_desktop_action(action, args, False, "denied by user", approved=False)
            return tool_error(f"Action '{action}' denied by user")

    # ── Execute ──────────────────────────────────────────────────────────
    from tools.computer_use import backend as B

    try:
        if action == "screenshot":
            b64 = B.screenshot()
            log_desktop_action("screenshot", {}, True)
            # Return multimodal result
            return json.dumps({
                "_multimodal": True,
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": b64,
                        },
                    }
                ],
                "text_summary": "Screenshot taken.",
            })

        elif action in ("click", "double_click", "right_click", "middle_click"):
            if coordinate is None:
                return tool_error("'coordinate' required for click actions")
            x, y = int(coordinate[0]), int(coordinate[1])
            if action == "click":
                B.click(x, y)
            elif action == "double_click":
                B.double_click(x, y)
            elif action == "right_click":
                B.right_click(x, y)
            elif action == "middle_click":
                B.middle_click(x, y)
            log_desktop_action(action, {"x": x, "y": y}, True)
            return json.dumps({"ok": True, "action": action, "x": x, "y": y})

        elif action == "move_mouse":
            if coordinate is None:
                return tool_error("'coordinate' required for move_mouse")
            x, y = int(coordinate[0]), int(coordinate[1])
            B.move_mouse(x, y, duration=duration)
            log_desktop_action("move_mouse", {"x": x, "y": y}, True)
            return json.dumps({"ok": True, "action": "move_mouse", "x": x, "y": y})

        elif action == "type":
            if not text:
                return tool_error("'text' required for type action")
            B.type_text(text, interval=interval)
            log_desktop_action("type", {"text": text}, True)
            return json.dumps({"ok": True, "typed": len(text)})

        elif action == "key":
            if not keys:
                return tool_error("'keys' required for key action")
            B.press_key(keys)
            log_desktop_action("key", {"keys": keys}, True)
            return json.dumps({"ok": True, "keys": keys})

        elif action == "scroll":
            coord = coordinate or [0, 0]
            x, y = int(coord[0]), int(coord[1])
            B.scroll(x, y, direction=direction or "down", amount=int(amount))
            log_desktop_action("scroll", {"x": x, "y": y, "dir": direction}, True)
            return json.dumps({"ok": True, "scrolled": direction or "down", "amount": amount})

        elif action == "drag":
            if from_coordinate is None or to_coordinate is None:
                return tool_error("'from_coordinate' and 'to_coordinate' required for drag")
            fx, fy = int(from_coordinate[0]), int(from_coordinate[1])
            tx, ty = int(to_coordinate[0]), int(to_coordinate[1])
            B.drag(fx, fy, tx, ty, duration=duration)
            log_desktop_action("drag", {"from": [fx, fy], "to": [tx, ty]}, True)
            return json.dumps({"ok": True, "dragged_to": [tx, ty]})

        elif action == "get_screen_size":
            w, h = B.get_screen_size()
            return json.dumps({"width": w, "height": h})

        elif action == "get_mouse_position":
            x, y = B.get_mouse_position()
            return json.dumps({"x": x, "y": y})

        elif action == "wait":
            secs = float(duration) if duration else 1.0
            B.wait(secs)
            return json.dumps({"ok": True, "waited": secs})

        else:
            return tool_error(f"Unknown action: {action!r}")

    except RuntimeError as exc:
        log_desktop_action(action, args, False, str(exc))
        return tool_error(str(exc))
    except Exception as exc:
        logger.exception("computer_use action=%s failed", action)
        log_desktop_action(action, args, False, str(exc))
        return tool_error(f"computer_use error: {exc}")


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _is_available() -> bool:
    """Return True when at least one backend can execute actions."""
    from tools.computer_use.pyautogui_backend import pyautogui_backend_available
    from tools.computer_use.cua_backend import cua_driver_binary_available
    return pyautogui_backend_available() or cua_driver_binary_available()


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

registry.register(
    name="computer_use",
    schema=COMPUTER_USE_SCHEMA,
    handler=_handle_computer_use,
    toolset="computer_use",
    check_fn=_is_available,
)

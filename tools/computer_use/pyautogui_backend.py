"""Cross-platform computer-use backend using pyautogui.

Supports Windows, macOS (without cua-driver), and Linux (X11/Wayland).
Requires: pyautogui, Pillow

Install:
    pip install pyautogui pillow
    # Linux also needs:
    pip install python3-xlib  # or python-xlib
"""

from __future__ import annotations

import base64
import io
import logging
import os
import sys
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_PLATFORM = sys.platform  # "linux", "darwin", "win32"


def pyautogui_backend_available() -> bool:
    """Return True when pyautogui is importable AND a display is reachable."""
    try:
        import pyautogui  # noqa: F401
    except ImportError:
        return False

    if _PLATFORM == "linux":
        display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        if not display:
            return False
        try:
            import pyautogui
            pyautogui.size()
        except Exception:
            return False

    return True


def _get_pyautogui():
    """Import and configure pyautogui (lazy, called only when needed)."""
    try:
        import pyautogui
    except ImportError as exc:
        raise RuntimeError(
            "pyautogui is not installed. Run: pip install pyautogui pillow"
        ) from exc

    pyautogui.FAILSAFE = True        # Move mouse to (0,0) to abort
    pyautogui.PAUSE = 0.05           # Small delay between calls for stability
    return pyautogui


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------

def screenshot(region: Optional[Tuple[int, int, int, int]] = None) -> str:
    """Take a screenshot and return it as base64-encoded PNG.

    Parameters
    ----------
    region : (left, top, width, height) or None for full screen
    """
    pya = _get_pyautogui()
    try:
        img = pya.screenshot(region=region)
    except Exception as exc:
        # Fallback: try PIL directly on Windows
        if _PLATFORM == "win32":
            from PIL import ImageGrab
            img = ImageGrab.grab(bbox=region)
        else:
            raise exc

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode("ascii")


# ---------------------------------------------------------------------------
# Mouse actions
# ---------------------------------------------------------------------------

def move_mouse(x: int, y: int, duration: float = 0.2) -> None:
    pya = _get_pyautogui()
    pya.moveTo(x, y, duration=duration)


def click(x: int, y: int, button: str = "left", clicks: int = 1,
          interval: float = 0.0) -> None:
    pya = _get_pyautogui()
    btn_map = {"left": "left", "right": "right", "middle": "middle"}
    pya.click(x, y, button=btn_map.get(button, "left"),
              clicks=clicks, interval=interval)


def double_click(x: int, y: int) -> None:
    pya = _get_pyautogui()
    pya.doubleClick(x, y)


def right_click(x: int, y: int) -> None:
    pya = _get_pyautogui()
    pya.rightClick(x, y)


def middle_click(x: int, y: int) -> None:
    pya = _get_pyautogui()
    pya.middleClick(x, y)


def drag(from_x: int, from_y: int, to_x: int, to_y: int,
         duration: float = 0.5, button: str = "left") -> None:
    pya = _get_pyautogui()
    pya.moveTo(from_x, from_y, duration=0.1)
    pya.dragTo(to_x, to_y, duration=duration, button=button)


def scroll(x: int, y: int, direction: str = "down", amount: int = 3) -> None:
    """Scroll at (x, y). direction: up/down/left/right."""
    pya = _get_pyautogui()
    pya.moveTo(x, y, duration=0.1)
    clicks = amount if direction == "up" else -amount
    if direction in ("up", "down"):
        pya.scroll(clicks)
    elif direction == "right":
        pya.hscroll(amount)
    elif direction == "left":
        pya.hscroll(-amount)


# ---------------------------------------------------------------------------
# Keyboard actions
# ---------------------------------------------------------------------------

def type_text(text: str, interval: float = 0.0) -> None:
    """Type text as keyboard input."""
    pya = _get_pyautogui()
    pya.typewrite(text, interval=interval)


def press_key(keys: str) -> None:
    """Press a key or key combination, e.g. 'ctrl+c', 'enter', 'escape'."""
    pya = _get_pyautogui()

    # Normalize aliases
    key_aliases = {
        "windows": "win", "winkey": "win", "super": "win",
        "cmd": "command",
        "control": "ctrl",
        "return": "enter",
        "esc": "escape",
        "del": "delete",
        "backspace": "backspace",
    }

    parts = [p.strip().lower() for p in keys.split("+") if p.strip()]
    normalized = [key_aliases.get(p, p) for p in parts]

    if len(normalized) == 1:
        pya.press(normalized[0])
    else:
        # Hold modifiers, tap the last key
        pya.hotkey(*normalized)


# ---------------------------------------------------------------------------
# Info queries
# ---------------------------------------------------------------------------

def get_screen_size() -> Tuple[int, int]:
    pya = _get_pyautogui()
    size = pya.size()
    return (size.width, size.height)


def get_mouse_position() -> Tuple[int, int]:
    pya = _get_pyautogui()
    pos = pya.position()
    return (pos.x, pos.y)


def wait(seconds: float) -> None:
    time.sleep(max(0.0, min(seconds, 30.0)))  # cap at 30s

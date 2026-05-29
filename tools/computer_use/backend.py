"""Unified cross-platform backend dispatcher.

Selects the right backend at call time:
  - macOS + cua-driver available → cua_backend (no focus steal)
  - Everything else → pyautogui_backend
"""

from __future__ import annotations

import logging
import sys
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

_PLATFORM = sys.platform


def _use_cua() -> bool:
    """Return True when cua-driver should be used (macOS + binary present)."""
    if _PLATFORM != "darwin":
        return False
    try:
        from tools.computer_use.cua_backend import cua_driver_binary_available
        return cua_driver_binary_available()
    except Exception:
        return False


def screenshot(region: Optional[Tuple[int, int, int, int]] = None) -> str:
    """Return base64-encoded PNG screenshot."""
    if _use_cua() and region is None:
        from tools.computer_use.cua_backend import screenshot as _ss
        return _ss()
    from tools.computer_use.pyautogui_backend import screenshot as _ss
    return _ss(region=region)


def click(x: int, y: int, button: str = "left") -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.click(x, y, button)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.click(x, y, button=button)


def double_click(x: int, y: int) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.double_click(x, y)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.double_click(x, y)


def right_click(x: int, y: int) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.right_click(x, y)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.right_click(x, y)


def middle_click(x: int, y: int) -> None:
    from tools.computer_use import pyautogui_backend as _b
    _b.middle_click(x, y)


def move_mouse(x: int, y: int, duration: float = 0.2) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.move_mouse(x, y)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.move_mouse(x, y, duration=duration)


def type_text(text: str, interval: float = 0.0) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.type_text(text)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.type_text(text, interval=interval)


def press_key(keys: str) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.press_key(keys)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.press_key(keys)


def scroll(x: int, y: int, direction: str = "down", amount: int = 3) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.scroll(x, y, direction, amount)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.scroll(x, y, direction=direction, amount=amount)


def drag(from_x: int, from_y: int, to_x: int, to_y: int,
         duration: float = 0.5) -> None:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        _b.drag(from_x, from_y, to_x, to_y)
    else:
        from tools.computer_use import pyautogui_backend as _b
        _b.drag(from_x, from_y, to_x, to_y, duration=duration)


def get_screen_size() -> Tuple[int, int]:
    if _use_cua():
        from tools.computer_use import cua_backend as _b
        return _b.get_screen_size()
    from tools.computer_use import pyautogui_backend as _b
    return _b.get_screen_size()


def get_mouse_position() -> Tuple[int, int]:
    from tools.computer_use import pyautogui_backend as _b
    return _b.get_mouse_position()


def wait(seconds: float) -> None:
    from tools.computer_use import pyautogui_backend as _b
    _b.wait(seconds)

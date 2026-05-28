"""Cross-platform backend for computer_use via pyautogui + OpenCV.

Works on Linux, Windows, and macOS. Implements the ComputerUseBackend
interface using pixel-coordinate-based actions instead of AX tree navigation.

Safety: FAILSAFE (upper-left corner abort), coordinate clamping, smooth mouse
movement. All destructive actions go through approval gating in tool.py.
"""

from __future__ import annotations

import base64
import io
import logging
import math
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import pyautogui

_PLATFORM = sys.platform  # "linux", "darwin", "win32"

# Platform-specific imports
try:
    import pygetwindow as gw
except ImportError:
    gw = None  # type: ignore[assignment]

from tools.computer_use.backend import (
    ActionResult,
    CaptureResult,
    ComputerUseBackend,
    UIElement,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform-specific key name normalization
# ---------------------------------------------------------------------------

_KEY_ALIASES: Dict[str, str] = {}
if _PLATFORM == "darwin":
    _KEY_ALIASES = {
        "command": "command", "cmd": "command",
        "control": "ctrl", "ctrl": "ctrl",
        "alt": "option", "option": "option",
        "shift": "shift", "fn": "fn",
        "win": "command", "super": "command",
    }
elif _PLATFORM == "win32":
    _KEY_ALIASES = {
        "command": "ctrl", "cmd": "ctrl",
        "control": "ctrl", "ctrl": "ctrl",
        "alt": "alt", "option": "alt",
        "shift": "shift", "fn": "fn",
        "win": "win", "super": "win",
    }
else:
    _KEY_ALIASES = {
        "command": "super", "cmd": "super",
        "control": "ctrl", "ctrl": "ctrl",
        "alt": "alt", "option": "alt",
        "shift": "shift", "fn": "fn",
        "win": "super", "super": "super",
    }


def _is_pyautogui_available() -> bool:
    """Return True if pyautogui can actually control the desktop."""
    try:
        if _PLATFORM == "linux":
            if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
                return False
        pyautogui.size()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Safety border — red pulsing border on screenshots when desktop control active
# ---------------------------------------------------------------------------

# Track border state for pulsing animation
_BORDER_FRAME = 0
_BORDER_MAX_FRAMES = 4
_BORDER_COLORS = [
    (220, 30, 30),   # bright red
    (255, 60, 60),   # lighter red
    (200, 20, 20),   # deep red
    (240, 40, 40),   # mid red
]


def _draw_safety_border(
    img_bytes: bytes,
    border_width: int = 10,
) -> bytes:
    """Draw a red safety border on the screenshot to indicate desktop control is active.

    Claude Code-style visual feedback — when FETIH controls the desktop,
    every screenshot gets a prominent red border so both the model and
    user can see that desktop automation is in progress.
    """
    global _BORDER_FRAME
    try:
        import cv2
        import numpy as np

        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return img_bytes

        h, w = img.shape[:2]
        color = _BORDER_COLORS[_BORDER_FRAME % _BORDER_MAX_FRAMES]
        _BORDER_FRAME += 1

        # BGR format for OpenCV
        bgr = (color[2], color[1], color[0])

        # Draw outer border rectangle
        cv2.rectangle(img, (0, 0), (w - 1, h - 1), bgr, border_width)

        # Draw corner accents (thicker corners for "danger" feel)
        corner_len = min(60, w // 6, h // 6)
        cv2.rectangle(img, (0, 0), (corner_len, border_width), bgr, -1)         # top-left h
        cv2.rectangle(img, (0, 0), (border_width, corner_len), bgr, -1)          # top-left v
        cv2.rectangle(img, (w - corner_len, 0), (w - 1, border_width), bgr, -1) # top-right h
        cv2.rectangle(img, (w - border_width, 0), (w - 1, corner_len), bgr, -1)  # top-right v
        cv2.rectangle(img, (0, h - border_width), (corner_len, h - 1), bgr, -1) # bottom-left h
        cv2.rectangle(img, (0, h - corner_len), (border_width, h - 1), bgr, -1)  # bottom-left v
        cv2.rectangle(img, (w - corner_len, h - border_width), (w - 1, h - 1), bgr, -1) # bottom-right h
        cv2.rectangle(img, (w - border_width, h - corner_len), (w - 1, h - 1), bgr, -1)  # bottom-right v

        # Draw status text in top-left
        status_text = "FETIH KONTROLUNDE"
        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale = 0.7
        thickness = 2
        (tw, th), baseline = cv2.getTextSize(status_text, font, font_scale, thickness)

        # Background box for text
        text_x = border_width + 10
        text_y = border_width + th + 10
        cv2.rectangle(
            img,
            (text_x - 6, text_y - th - 6),
            (text_x + tw + 6, text_y + baseline + 6),
            (0, 0, 0),
            -1,
        )
        cv2.putText(
            img, status_text, (text_x, text_y),
            font, font_scale, bgr, thickness, cv2.LINE_AA,
        )

        # Draw small mouse icon hint in bottom-right
        hint_text = "FAILSAFE: fareyi sol ust koseye cek = DURDUR"
        hint_scale = 0.35
        hint_thickness = 1
        (hw, hh), _ = cv2.getTextSize(hint_text, font, hint_scale, hint_thickness)
        cv2.putText(
            img, hint_text,
            (w - hw - border_width - 6, h - border_width - 8),
            font, hint_scale, (180, 180, 180), hint_thickness, cv2.LINE_AA,
        )

        _, buf = cv2.imencode(".png", img)
        return buf.tobytes()
    except ImportError:
        return img_bytes


def _is_border_enabled() -> bool:
    """Check if safety border should be drawn."""
    return os.environ.get("FETIH_DESKTOP_ENABLED", "").strip() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Grid-based SOM overlay
# ---------------------------------------------------------------------------

def _draw_som_grid(
    img_bytes: bytes,
    grid_rows: int = 12,
    grid_cols: int = 16,
) -> Tuple[bytes, int, int, List[UIElement]]:
    """Draw a numbered grid overlay on a screenshot for Set-of-Mark mode."""
    try:
        import cv2
        import numpy as np

        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return img_bytes, 0, 0, []

        h, w = img.shape[:2]
        cell_h = max(1, h // grid_rows)
        cell_w = max(1, w // grid_cols)

        elements: List[UIElement] = []
        cell_num = 1

        for row in range(grid_rows):
            for col in range(grid_cols):
                x1 = col * cell_w
                y1 = row * cell_h
                x2 = min(x1 + cell_w, w)
                y2 = min(y1 + cell_h, h)
                cx = (x1 + x2) // 2
                cy = (y1 + y2) // 2

                cv2.rectangle(img, (x1, y1), (x2, y2), (0, 255, 0), 1)

                label = str(cell_num)
                (tw, th), baseline = cv2.getTextSize(
                    label, cv2.FONT_HERSHEY_SIMPLEX, 0.35, 1
                )
                tx = max(0, cx - tw // 2)
                ty = cy + th // 2
                cv2.rectangle(
                    img,
                    (tx - 2, ty - th - 2),
                    (tx + tw + 2, ty + baseline + 2),
                    (0, 0, 0),
                    -1,
                )
                cv2.putText(
                    img, label, (tx, ty),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.35, (0, 255, 0), 1,
                    cv2.LINE_AA,
                )

                elements.append(UIElement(
                    index=cell_num,
                    role="grid_cell",
                    label=f"cell({row},{col}) cx={cx} cy={cy}",
                    bounds=(x1, y1, x2 - x1, y2 - y1),
                ))
                cell_num += 1

        _, buf = cv2.imencode(".png", img)
        return buf.tobytes(), w, h, elements
    except ImportError:
        return img_bytes, 0, 0, []


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _clamp_coords(x: int, y: int) -> Tuple[int, int]:
    sw, sh = pyautogui.size()
    return (max(0, min(x, sw - 1)), max(0, min(y, sh - 1)))


def _smooth_move(x: int, y: int, duration: float = 0.3) -> None:
    x, y = _clamp_coords(x, y)
    try:
        pyautogui.moveTo(x, y, duration=duration)
    except Exception:
        pyautogui.moveTo(x, y)


def _normalize_key_combo(keys: str) -> Tuple[str, ...]:
    parts = [p.strip().lower() for p in re.split(r'\s*\+\s*', keys) if p.strip()]
    return tuple(_KEY_ALIASES.get(p, p) for p in parts)


def _hold_modifiers(modifiers: List[str]) -> None:
    for mod in modifiers:
        try:
            pyautogui.keyDown(_KEY_ALIASES.get(mod.lower(), mod.lower()))
        except Exception:
            pass


def _release_modifiers(modifiers: List[str]) -> None:
    for mod in reversed(modifiers):
        try:
            pyautogui.keyUp(_KEY_ALIASES.get(mod.lower(), mod.lower()))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# PyAutoGUI Backend
# ---------------------------------------------------------------------------

class PyAutoGUIBackend(ComputerUseBackend):
    """Cross-platform desktop control via pyautogui + OpenCV."""

    def __init__(self, grid_rows: int = 12, grid_cols: int = 16) -> None:
        self._grid_rows = grid_rows
        self._grid_cols = grid_cols
        self._started = False
        pyautogui.FAILSAFE = True
        pyautogui.PAUSE = 0.1

    # ── Lifecycle ────────────────────────────────────────────────────

    def start(self) -> None:
        if self._started:
            return
        if not _is_pyautogui_available():
            raise RuntimeError(
                "pyautogui cannot control this desktop. "
                "On Linux, ensure DISPLAY or WAYLAND_DISPLAY is set. "
                "On all platforms, a GUI session must be active."
            )
        self._started = True
        logger.info("PyAutoGUI backend started (platform=%s)", _PLATFORM)

    def stop(self) -> None:
        self._started = False

    def is_available(self) -> bool:
        return self._started and _is_pyautogui_available()

    # ── Capture ──────────────────────────────────────────────────────

    def capture(self, mode: str = "som", app: Optional[str] = None) -> CaptureResult:
        if mode == "ax":
            return self._capture_ax(app)
        return self._capture_screenshot(mode, app)

    def _capture_screenshot(self, mode: str, app: Optional[str] = None) -> CaptureResult:
        try:
            screenshot = pyautogui.screenshot()
        except Exception as e:
            raise RuntimeError(f"Screenshot failed: {e}") from e

        w, h = screenshot.size
        buf = io.BytesIO()
        screenshot.save(buf, format="PNG")
        img_bytes = buf.getvalue()

        # Draw safety border when desktop control is active
        if _is_border_enabled():
            try:
                img_bytes = _draw_safety_border(img_bytes)
            except Exception as e:
                logger.warning("Safety border failed: %s", e)

        elements: List[UIElement] = []
        png_b64 = base64.b64encode(img_bytes).decode("ascii")

        if mode == "som":
            try:
                overlay_bytes, ow, oh, elements = _draw_som_grid(
                    img_bytes, self._grid_rows, self._grid_cols
                )
                if overlay_bytes:
                    png_b64 = base64.b64encode(overlay_bytes).decode("ascii")
                    w, h = ow, oh
            except Exception as e:
                logger.warning("SOM grid overlay failed: %s", e)

        return CaptureResult(
            mode=mode, width=w, height=h,
            png_b64=png_b64, elements=elements,
            app=app or "", window_title=self._active_window_title() or "",
            png_bytes_len=len(png_b64),
        )

    def _capture_ax(self, app: Optional[str] = None) -> CaptureResult:
        elements: List[UIElement] = []
        try:
            wins = self._list_windows_raw()
            for i, win in enumerate(wins[:50], 1):
                elements.append(UIElement(
                    index=i, role="window",
                    label=win.get("title", ""),
                    bounds=(
                        win.get("left", 0), win.get("top", 0),
                        win.get("width", 0), win.get("height", 0),
                    ),
                ))
        except Exception as e:
            logger.warning("Failed to list windows: %s", e)

        w, h = pyautogui.size()
        return CaptureResult(
            mode="ax", width=w, height=h,
            png_b64=None, elements=elements,
            app=app or "", window_title=self._active_window_title() or "",
        )

    # ── Pointer ──────────────────────────────────────────────────────

    def click(
        self, *, element=None, x=None, y=None,
        button="left", click_count=1, modifiers=None,
    ) -> ActionResult:
        if element is not None:
            return ActionResult(False, "click",
                "element-index clicks not supported; use pixel coordinates")
        if x is None or y is None:
            return ActionResult(False, "click", "x,y coordinates required")
        try:
            px, py = _clamp_coords(x, y)
            if modifiers:
                _hold_modifiers(modifiers)
            _smooth_move(px, py)
            pyautogui.click(px, py, button=button, clicks=click_count)
            if modifiers:
                _release_modifiers(modifiers)
            return ActionResult(True, "click",
                f"{button} click x{click_count} at ({px},{py})")
        except pyautogui.FailSafeException:
            return ActionResult(False, "click", "FAILSAFE: mouse at corner (0,0)")
        except Exception as e:
            return ActionResult(False, "click", str(e))

    def drag(
        self, *, from_element=None, to_element=None,
        from_xy=None, to_xy=None, button="left", modifiers=None,
    ) -> ActionResult:
        if from_element is not None or to_element is not None:
            return ActionResult(False, "drag",
                "element-index drag not supported; use pixel coordinates")
        if not from_xy or not to_xy:
            return ActionResult(False, "drag",
                "from_coordinate and to_coordinate required")
        try:
            fx, fy = _clamp_coords(*from_xy)
            tx, ty = _clamp_coords(*to_xy)
            if modifiers:
                _hold_modifiers(modifiers)
            _smooth_move(fx, fy)
            pyautogui.drag(tx - fx, ty - fy, button=button, duration=0.5)
            if modifiers:
                _release_modifiers(modifiers)
            return ActionResult(True, "drag",
                f"dragged ({fx},{fy}) → ({tx},{ty})")
        except pyautogui.FailSafeException:
            return ActionResult(False, "drag", "FAILSAFE triggered")
        except Exception as e:
            return ActionResult(False, "drag", str(e))

    def scroll(
        self, *, direction="down", amount=3, element=None,
        x=None, y=None, modifiers=None,
    ) -> ActionResult:
        if element is not None:
            return ActionResult(False, "scroll",
                "element-index scroll not supported; use pixel coordinates")
        try:
            if x is not None and y is not None:
                _smooth_move(x, y)
            clicks = amount if direction in ("up", "left") else -amount
            if modifiers:
                _hold_modifiers(modifiers)
            if direction in ("left", "right"):
                pyautogui.hscroll(clicks)
            else:
                pyautogui.scroll(clicks)
            if modifiers:
                _release_modifiers(modifiers)
            return ActionResult(True, "scroll", f"scrolled {direction} x{amount}")
        except pyautogui.FailSafeException:
            return ActionResult(False, "scroll", "FAILSAFE triggered")
        except Exception as e:
            return ActionResult(False, "scroll", str(e))

    # ── Keyboard ─────────────────────────────────────────────────────

    def type_text(self, text: str) -> ActionResult:
        try:
            interval = max(0.05, min(0.2, 12.0 / max(1, len(text))))
            pyautogui.write(text, interval=interval)
            return ActionResult(True, "type", f"typed {len(text)} chars")
        except pyautogui.FailSafeException:
            return ActionResult(False, "type", "FAILSAFE triggered")
        except Exception as e:
            return ActionResult(False, "type", str(e))

    def key(self, keys: str) -> ActionResult:
        try:
            normalized = _normalize_key_combo(keys)
            pyautogui.hotkey(*normalized)
            return ActionResult(True, "key", f"pressed {keys!r}")
        except pyautogui.FailSafeException:
            return ActionResult(False, "key", "FAILSAFE triggered")
        except Exception as e:
            return ActionResult(False, "key", str(e))

    # ── Set value ────────────────────────────────────────────────────

    def set_value(self, value: str, element: Optional[int] = None) -> ActionResult:
        if element is not None:
            return ActionResult(False, "set_value",
                "element-index set_value not supported on pyautogui backend")
        try:
            pyautogui.write(value, interval=0.05)
            return ActionResult(True, "set_value", f"set value to {value!r}")
        except Exception as e:
            return ActionResult(False, "set_value", str(e))

    # ── Introspection ────────────────────────────────────────────────

    def list_apps(self) -> List[Dict[str, Any]]:
        return self._list_windows_raw()

    def _list_windows_raw(self) -> List[Dict[str, Any]]:
        windows: List[Dict[str, Any]] = []
        if gw is None:
            return windows
        try:
            for w in gw.getAllWindows():
                title = (w.title or "").strip()
                if not title:
                    continue
                windows.append({
                    "title": title,
                    "app_name": title.rsplit(" - ", 1)[-1],
                    "left": w.left, "top": w.top,
                    "width": w.width, "height": w.height,
                    "visible": not (w.isMinimized if hasattr(w, 'isMinimized') else False),
                    "active": w.isActive if hasattr(w, 'isActive') else False,
                })
        except Exception as e:
            logger.warning("Failed to list windows: %s", e)
        return windows

    def focus_app(self, app: str, raise_window: bool = False) -> ActionResult:
        if gw is None:
            return ActionResult(False, "focus_app",
                "pygetwindow not available on this platform")
        try:
            query = app.lower()
            matched = None
            for w in gw.getAllWindows():
                t = (w.title or "").lower()
                if query in t:
                    matched = w
                    break
            if matched is None:
                return ActionResult(False, "focus_app",
                    f"no window matching {app!r}")
            if raise_window:
                try:
                    matched.restore()
                    matched.activate()
                except Exception:
                    pass
            cx = matched.left + matched.width // 2
            cy = matched.top + matched.height // 2
            _smooth_move(cx, cy)
            pyautogui.click()
            return ActionResult(True, "focus_app",
                f"focused {matched.title!r}")
        except pyautogui.FailSafeException:
            return ActionResult(False, "focus_app", "FAILSAFE triggered")
        except Exception as e:
            return ActionResult(False, "focus_app", str(e))

    def _active_window_title(self) -> Optional[str]:
        if gw is None:
            return None
        try:
            active = gw.getActiveWindow()
            return active.title if active else None
        except Exception:
            return None


def pyautogui_backend_available() -> bool:
    """Check if the pyautogui backend can be used on this host."""
    return _is_pyautogui_available()

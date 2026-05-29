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
# Safety border — DISPATCH-STYLE red frame when desktop control is active
# ---------------------------------------------------------------------------
# Claude Code dispatch mode benzeri: ekranin tamamen cevresi kirmizi cerceve,
# pulsing animasyon, yari-saydam kirmizi ton, "FETIH KONTROLUNDE" yazisi.
# Hem AI hem kullanici masaustu otomasyonunun aktif oldugunu hemen anlar.

_BORDER_FRAME = 0
_BORDER_MAX_FRAMES = 6
_BORDER_COLORS = [
    (220, 25, 25),   # bright red
    (240, 35, 35),   # hot red
    (200, 20, 20),   # deep red
    (255, 50, 50),   # pulse peak
    (210, 28, 28),   # darkening
    (235, 40, 40),   # recovering
]

# Diagonal danger stripes pattern (pre-computed tile, 48x48)
_DANGER_STRIPE = None
_DANGER_STRIPE_SIZE = 48


def _get_danger_stripe():
    """Create a 45-degree diagonal red/black danger stripe tile."""
    global _DANGER_STRIPE
    if _DANGER_STRIPE is not None:
        return _DANGER_STRIPE
    try:
        import numpy as np
        size = _DANGER_STRIPE_SIZE
        tile = np.zeros((size, size, 3), dtype=np.uint8)
        # Draw diagonal stripes: every 12px band
        for i in range(-size, size * 2, 12):
            for x in range(size):
                y = x + i
                if 0 <= y < size:
                    # Determine stripe color: alternate red/black
                    band_idx = (i // 12) % 2
                    if band_idx == 0:
                        tile[y, x] = (35, 25, 200)   # dark red (BGR)
                    else:
                        tile[y, x] = (15, 5, 5)      # near black
        _DANGER_STRIPE = tile
        return tile
    except ImportError:
        return None


def _draw_safety_border(
    img_bytes: bytes,
    border_width: int = 0,  # 0 = auto: 4% of min dimension
) -> bytes:
    """Draw a dispatch-style red safety border on the screenshot.

    Claude Code dispatch-mode inspired: thick red frame around the entire
    screen, pulsing color animation, danger stripes in corners, semi-transparent
    red overlay, and prominent "FETIH KONTROLUNDE" text.

    The border is drawn OUTSIDE the content — original image is preserved,
    expanded to include the red frame. This way nothing is hidden.
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

        # Auto border width: ~4% of min dimension (≈43px for 1080p)
        if border_width <= 0:
            border_width = max(25, min(h, w) // 25)

        bw = border_width

        # Pulsing color
        color = _BORDER_COLORS[_BORDER_FRAME % _BORDER_MAX_FRAMES]
        _BORDER_FRAME += 1
        bgr = (color[2], color[1], color[0])           # main red
        bgr_dark = (color[2] // 2, color[1] // 3, color[0] // 3)  # darker shade

        # === Expand canvas: original image + border all around ===
        new_h = h + bw * 2
        new_w = w + bw * 2
        canvas = np.zeros((new_h, new_w, 3), dtype=np.uint8)
        canvas[:, :] = bgr  # Fill entire canvas with red

        # Place original image centered
        canvas[bw:bw + h, bw:bw + w] = img

        # === Inner edge (transition line between border and content) ===
        inner_color = bgr_dark
        cv2.rectangle(canvas,
                      (bw - 2, bw - 2),
                      (bw + w + 1, bw + h + 1),
                      inner_color, 2)

        # === Danger stripes in corners (4 corners) ===
        stripe_tile = _get_danger_stripe()
        if stripe_tile is not None:
            ss = _DANGER_STRIPE_SIZE
            # Top-left corner stripes
            for y in range(0, bw, ss):
                for x in range(0, bw, ss):
                    sy = min(ss, bw - y)
                    sx = min(ss, bw - x)
                    if sy > 0 and sx > 0:
                        canvas[y:y + sy, x:x + sx] = stripe_tile[:sy, :sx]

            # Top-right corner stripes
            for y in range(0, bw, ss):
                for x in range(0, bw, ss):
                    sy = min(ss, bw - y)
                    sx = min(ss, bw - x)
                    if sy > 0 and sx > 0:
                        dx = new_w - bw + x
                        canvas[y:y + sy, dx:dx + sx] = stripe_tile[:sy, :sx]

            # Bottom-left corner stripes
            for y in range(0, bw, ss):
                for x in range(0, bw, ss):
                    sy = min(ss, bw - y)
                    sx = min(ss, bw - x)
                    if sy > 0 and sx > 0:
                        dy = new_h - bw + y
                        canvas[dy:dy + sy, x:x + sx] = stripe_tile[:sy, :sx]

            # Bottom-right corner stripes
            for y in range(0, bw, ss):
                for x in range(0, bw, ss):
                    sy = min(ss, bw - y)
                    sx = min(ss, bw - x)
                    if sy > 0 and sx > 0:
                        dy = new_h - bw + y
                        dx = new_w - bw + x
                        canvas[dy:dy + sy, dx:dx + sx] = stripe_tile[:sy, :sx]

        # === Top bar: "FETIH KONTROLUNDE" label ===
        font = cv2.FONT_HERSHEY_SIMPLEX
        label = "FETIH KONTROLUNDE"
        # Scale font to be prominent but fit in the border
        label_scale = min(bw / 40.0, 1.5)
        label_thickness = max(2, int(bw / 12))
        (tw, th), baseline = cv2.getTextSize(label, font, label_scale, label_thickness)

        # Center the text in the top border
        lx = (new_w - tw) // 2
        ly = bw // 2 + th // 2

        # Text shadow
        cv2.putText(canvas, label, (lx + 2, ly + 2),
                    font, label_scale, (0, 0, 0),
                    label_thickness + 1, cv2.LINE_AA)
        # Text in white
        cv2.putText(canvas, label, (lx, ly),
                    font, label_scale, (255, 255, 255),
                    label_thickness, cv2.LINE_AA)

        # === Bottom bar: FAILSAFE hint ===
        hint = "FAILSAFE: fareyi sol ust koseye cek = DURDUR"
        hint_scale = min(bw / 100.0, 0.5)
        hint_thick = max(1, int(bw / 20))
        (hw, hh), _ = cv2.getTextSize(hint, font, hint_scale, hint_thick)
        hx = (new_w - hw) // 2
        hy = new_h - bw // 2 + hh // 2
        cv2.putText(canvas, hint, (hx, hy),
                    font, hint_scale, (200, 200, 200),
                    hint_thick, cv2.LINE_AA)

        # === Semi-transparent red overlay on content (subtle, 5% opacity) ===
        overlay = canvas[bw:bw + h, bw:bw + w].copy()
        red_tint = np.full_like(overlay, bgr_dark)
        canvas[bw:bw + h, bw:bw + w] = cv2.addWeighted(overlay, 0.90, red_tint, 0.10, 0)

        # === Pulsing glow effect: draw a thin white/yellow border on the inner edge ===
        pulse_alpha = (_BORDER_FRAME % _BORDER_MAX_FRAMES) / float(_BORDER_MAX_FRAMES)
        glow_bgr = (
            int(80 + 80 * pulse_alpha),     # B
            int(180 + 60 * pulse_alpha),     # G
            int(180 + 75 * pulse_alpha),     # R
        )
        cv2.rectangle(canvas,
                      (bw - 2, bw - 2),
                      (bw + w + 1, bw + h + 1),
                      glow_bgr, 3)

        _, buf = cv2.imencode(".png", canvas)
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
        """Stop desktop control and return focus to the terminal."""
        self._started = False
        # Try to bring the terminal back to front when stopping
        try:
            self.focus_app("terminal", raise_window=True)
        except Exception:
            pass

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
                # Update dimensions: border expands the canvas
                import cv2, numpy as np
                nparr = np.frombuffer(img_bytes, np.uint8)
                bordered = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if bordered is not None:
                    h, w = bordered.shape[:2]
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

    # Known terminal window title keywords by platform
    _TERMINAL_KEYWORDS = [
        "terminal", "gnome-terminal", "konsole", "xfce4-terminal",
        "alacritty", "kitty", "tilix", "terminator", "rxvt",
        "iterm2", "iterm", "powershell", "cmd", "command prompt",
        "windows terminal", "wt", "wezterm", "foot", "st-", "urxvt",
        "cool-retro-term", "hyper", "tabby",
    ]

    def focus_app(self, app: str, raise_window: bool = False) -> ActionResult:
        # Expand "terminal" to match all known terminal apps
        query_lower = app.lower()
        if query_lower in ("terminal", "term", "console"):
            queries = self._TERMINAL_KEYWORDS
        else:
            queries = [query_lower]

        # === Strategy 1: pygetwindow (cross-platform, most reliable) ===
        if gw is not None:
            try:
                matched = None
                all_windows = gw.getAllWindows()
                for q in queries:
                    for w in all_windows:
                        t = (w.title or "").lower()
                        if q in t:
                            matched = w
                            break
                    if matched:
                        break
                if matched is not None:
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
                logger.warning("pygetwindow focus failed: %s", e)

        # === Strategy 2: xdotool on Linux X11 ===
        if _PLATFORM == "linux":
            try:
                import subprocess
                for q in queries:
                    r = subprocess.run(
                        ["xdotool", "search", "--name", q],
                        capture_output=True, text=True, timeout=3,
                    )
                    if r.returncode == 0 and r.stdout.strip():
                        wid = r.stdout.strip().split("\n")[0]
                        subprocess.run(
                            ["xdotool", "windowactivate", wid],
                            timeout=3,
                        )
                        return ActionResult(True, "focus_app",
                            f"focused window matching {q!r} (xdotool)")
            except Exception as e:
                logger.warning("xdotool focus failed: %s", e)

            # Strategy 3: wmctrl fallback
            try:
                import subprocess
                for q in queries:
                    r = subprocess.run(
                        ["wmctrl", "-a", q],
                        capture_output=True, text=True, timeout=3,
                    )
                    if r.returncode == 0:
                        return ActionResult(True, "focus_app",
                            f"focused window matching {q!r} (wmctrl)")
            except Exception as e:
                logger.warning("wmctrl focus failed: %s", e)

        # === Strategy 4: Alt+Tab on all platforms (last resort) ===
        try:
            pyautogui.keyDown("alt")
            pyautogui.press("tab")
            pyautogui.keyUp("alt")
            return ActionResult(True, "focus_app",
                "used Alt+Tab to switch windows")
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

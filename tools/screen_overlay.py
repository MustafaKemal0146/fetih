"""Windows-only red gradient screen-border overlay.

Shows a click-through, always-on-top red gradient frame around the WHOLE
screen while the AI controls the desktop (Claude computer-use style). The
overlay does not block user input — clicks pass straight through the
transparent interior, so the failsafe (mouse → top-left corner) still works.

This module is a no-op on every platform except Windows. On Linux/macOS the
public functions return immediately, so POSIX behaviour is untouched.
"""

from __future__ import annotations

import sys
import threading

_IS_WINDOWS = sys.platform == "win32"

# Color that becomes fully transparent + click-through. Picked to be visually
# indistinguishable from black but unlikely to collide with the gradient bands.
_CHROMA_KEY = "#010101"

# How thick the glowing border is, in pixels.
_BORDER = 46

_lock = threading.Lock()
_thread: "threading.Thread | None" = None
_root = None  # tkinter root, owned by the overlay thread


def _lerp(a: int, b: int, t: float) -> int:
    return int(round(a + (b - a) * t))


def _gradient_color(t: float) -> str:
    """t=0 outer edge (bright red) → t=1 inner edge (fades into chroma key)."""
    # Bright red (#FF1A1A) fading toward the chroma key so it blends into
    # transparency at the inner edge instead of cutting off hard.
    r = _lerp(0xFF, 0x01, t)
    g = _lerp(0x1A, 0x01, t)
    b = _lerp(0x1A, 0x01, t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _make_clickthrough(hwnd: int) -> None:
    """Add WS_EX_TRANSPARENT so the window ignores the mouse (clicks pass through).

    SetWindowLongW resets the layered color-key that Tk installed for
    "-transparentcolor", so we must re-apply it afterwards or the whole window
    turns opaque black.
    """
    import ctypes

    GWL_EXSTYLE = -20
    WS_EX_LAYERED = 0x00080000
    WS_EX_TRANSPARENT = 0x00000020
    LWA_COLORKEY = 0x00000001
    user32 = ctypes.windll.user32

    style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
    user32.SetWindowLongW(
        hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED | WS_EX_TRANSPARENT
    )
    # Re-establish the chroma key as a COLORREF (0x00BBGGRR).
    r = int(_CHROMA_KEY[1:3], 16)
    g = int(_CHROMA_KEY[3:5], 16)
    b = int(_CHROMA_KEY[5:7], 16)
    colorref = (b << 16) | (g << 8) | r
    user32.SetLayeredWindowAttributes(hwnd, colorref, 0, LWA_COLORKEY)


def _run_overlay() -> None:
    global _root
    import tkinter as tk

    root = tk.Tk()
    _root = root
    root.overrideredirect(True)  # no title bar / borders
    root.attributes("-topmost", True)
    # NOTE: do NOT set "-alpha" here. On Windows, whole-window alpha and
    # "-transparentcolor" are mutually exclusive — setting alpha dims the
    # entire screen and the transparent (click-through) center stops working.

    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"{sw}x{sh}+0+0")
    root.config(bg=_CHROMA_KEY)
    # Make the chroma-key color transparent (and, with the ex-style below,
    # click-through over those pixels).
    root.attributes("-transparentcolor", _CHROMA_KEY)

    canvas = tk.Canvas(
        root, width=sw, height=sh, highlightthickness=0, bg=_CHROMA_KEY
    )
    canvas.pack(fill="both", expand=True)

    # Draw the gradient as nested rectangle outlines, one per pixel of border
    # thickness, interpolating bright-red → chroma-key from outside in.
    for i in range(_BORDER):
        t = i / float(_BORDER - 1)
        color = _gradient_color(t)
        canvas.create_rectangle(
            i, i, sw - 1 - i, sh - 1 - i, outline=color, width=1
        )

    root.update_idletasks()
    try:
        _make_clickthrough(root.winfo_id())
    except Exception:
        pass  # without click-through the frame still shows; failsafe still works

    root.mainloop()


def show() -> None:
    """Show the red gradient screen border. No-op off Windows / if already shown."""
    global _thread
    if not _IS_WINDOWS:
        return
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        t = threading.Thread(target=_run_overlay, name="fetih-screen-overlay", daemon=True)
        _thread = t
        t.start()


def hide() -> None:
    """Hide the overlay. No-op off Windows / if not shown."""
    global _thread, _root
    if not _IS_WINDOWS:
        return
    with _lock:
        root = _root
        if root is not None:
            try:
                root.after(0, root.destroy)
            except Exception:
                pass
        _root = None
        _thread = None


__all__ = ["show", "hide"]

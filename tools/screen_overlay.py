"""Cross-platform red gradient screen-border overlay.

Shows a click-through, always-on-top red gradient frame around the WHOLE
screen while the AI controls the desktop (Claude computer-use style). The
overlay does not block user input — clicks pass straight through the
transparent interior, so the failsafe (mouse → top-left corner) still works.

Platform support:
  • Windows  — Win32 layered windows + WS_EX_TRANSPARENT (exact pixel click-through)
  • Linux    — X11 Shape extension for input masking (fallback: visual-only, no click-through)
  • macOS    — Visual overlay only (click-through unavailable via tkinter/Cocoa)
"""

from __future__ import annotations

import sys
import threading

_IS_WINDOWS = sys.platform == "win32"
_IS_LINUX = sys.platform == "linux"

# Color that becomes fully transparent + click-through. Picked to be visually
# indistinguishable from black but unlikely to collide with the gradient bands.
_CHROMA_KEY = "#010101"

# How thick the glowing border is, in pixels.
_BORDER = 46

_lock = threading.Lock()
_thread: "threading.Thread | None" = None
_root = None  # tkinter root, owned by the overlay thread

# ---------------------------------------------------------------------------
# Gradient helpers (cross-platform)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Windows click-through (Win32 layered windows)
# ---------------------------------------------------------------------------


def _make_clickthrough_windows(hwnd: int) -> None:
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


# ---------------------------------------------------------------------------
# Linux click-through (X11 Shape extension — input masking)
# ---------------------------------------------------------------------------


def _make_clickthrough_linux(root: "tk.Tk") -> None:  # type: ignore[name-defined]  # noqa: F821
    """Set the X11 input shape so only the border region receives mouse events.

    Calls through to ``XShapeCombineRectangles`` (Shape extension) via ctypes,
    so there is **no** dependency on python-xlib.  If the X11 libraries cannot
    be found the function returns silently — the visual overlay still renders,
    only click-through is skipped.
    """
    import ctypes
    import ctypes.util

    libX11_path = ctypes.util.find_library("X11")
    libXext_path = ctypes.util.find_library("Xext")
    if not libX11_path or not libXext_path:
        return  # X11 not available (e.g. pure Wayland without XWayland)

    try:
        libX11 = ctypes.CDLL(libX11_path)
        libXext = ctypes.CDLL(libXext_path)
    except OSError:
        return

    # Open display connection.  None → $DISPLAY
    display = libX11.XOpenDisplay(None)
    if not display:
        return

    try:
        xid = root.winfo_id()
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        bw = _BORDER

        # XRectangle: short x, short y, unsigned short width, unsigned short height
        class _XRectangle(ctypes.Structure):
            _fields_ = [
                ("x", ctypes.c_short),
                ("y", ctypes.c_short),
                ("width", ctypes.c_ushort),
                ("height", ctypes.c_ushort),
            ]

        # Carve out the interior — define the four border bands as the input
        # region.  Everything outside these four rectangles (the transparent
        # center) passes clicks through to windows underneath.
        rects = [
            _XRectangle(0, 0, sw, bw),                              # top band
            _XRectangle(0, sh - bw, sw, bw),                        # bottom band
            _XRectangle(0, bw, bw, sh - 2 * bw),                    # left band
            _XRectangle(sw - bw, bw, bw, sh - 2 * bw),              # right band
        ]
        rect_array = (_XRectangle * len(rects))(*rects)

        # X11 constants
        ShapeInput = 2   # input region
        ShapeSet = 0     # replace existing shape

        libXext.XShapeCombineRectangles(
            ctypes.c_void_p(display),
            ctypes.c_ulong(xid),
            ShapeInput,
            0, 0,  # x_off, y_off
            rect_array,
            len(rects),
            ShapeSet,
            0,  # ordering: Unsorted
        )
        libX11.XFlush(display)
    except Exception:
        pass
    finally:
        libX11.XCloseDisplay(display)


# ---------------------------------------------------------------------------
# Overlay runner (cross-platform tkinter window)
# ---------------------------------------------------------------------------


def _run_overlay() -> None:
    global _root
    import tkinter as tk

    root = tk.Tk()
    _root = root
    root.overrideredirect(True)  # no title bar / borders
    root.attributes("-topmost", True)
    # NOTE: do NOT set "-alpha" here — whole-window alpha and
    # "-transparentcolor" are mutually exclusive. Setting alpha dims the
    # entire screen and the transparent (click-through) center stops working.

    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"{sw}x{sh}+0+0")
    root.config(bg=_CHROMA_KEY)
    # Make the chroma-key color transparent.
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

    # Apply platform-specific click-through so the center passes clicks/mouse
    # events through to windows underneath.
    if _IS_WINDOWS:
        try:
            _make_clickthrough_windows(root.winfo_id())
        except Exception:
            pass
    elif _IS_LINUX:
        try:
            _make_clickthrough_linux(root)
        except Exception:
            pass
    # macOS: no click-through via tkinter. The visual overlay still shows.

    root.mainloop()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def show() -> None:
    """Show the red gradient screen border (all platforms).

    No-op if the overlay is already visible.  Runs the tkinter mainloop on
    a daemon thread so it never blocks the caller.
    """
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        t = threading.Thread(
            target=_run_overlay, name="fetih-screen-overlay", daemon=True,
        )
        _thread = t
        t.start()


def hide() -> None:
    """Hide the overlay (all platforms).  No-op if not shown."""
    global _thread, _root
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

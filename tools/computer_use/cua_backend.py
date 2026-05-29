"""macOS-only background computer-use backend via cua-driver.

cua-driver is a SkyLight-based binary that controls macOS without
stealing cursor focus. On non-macOS platforms this module provides
availability stubs only.

Docs: https://github.com/trycua/cua
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_IS_MACOS = sys.platform == "darwin"


def cua_driver_binary_available() -> bool:
    """Return True when the cua-driver binary is on PATH (macOS only)."""
    if not _IS_MACOS:
        return False
    return shutil.which("cua-driver") is not None


def _call_cua(args: list, timeout: int = 10) -> Dict[str, Any]:
    """Invoke cua-driver CLI and return parsed JSON output."""
    try:
        result = subprocess.run(
            ["cua-driver"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"cua-driver exit {result.returncode}")
        return json.loads(result.stdout or "{}")
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("cua-driver timed out") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"cua-driver returned invalid JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------

def screenshot() -> str:
    """Take a macOS screenshot via cua-driver, return base64 PNG."""
    if not _IS_MACOS:
        raise RuntimeError("cua-driver is macOS only")
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        tmp_path = f.name
    try:
        _call_cua(["screenshot", "--output", tmp_path])
        with open(tmp_path, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Mouse / keyboard wrappers
# ---------------------------------------------------------------------------

def click(x: int, y: int, button: str = "left") -> None:
    _call_cua(["click", str(x), str(y), "--button", button])


def double_click(x: int, y: int) -> None:
    _call_cua(["click", str(x), str(y), "--clicks", "2"])


def right_click(x: int, y: int) -> None:
    _call_cua(["click", str(x), str(y), "--button", "right"])


def move_mouse(x: int, y: int) -> None:
    _call_cua(["move", str(x), str(y)])


def type_text(text: str) -> None:
    _call_cua(["type", text])


def press_key(keys: str) -> None:
    _call_cua(["key", keys])


def scroll(x: int, y: int, direction: str = "down", amount: int = 3) -> None:
    _call_cua(["scroll", str(x), str(y), "--direction", direction, "--amount", str(amount)])


def drag(from_x: int, from_y: int, to_x: int, to_y: int) -> None:
    _call_cua(["drag",
               str(from_x), str(from_y),
               str(to_x), str(to_y)])


def get_screen_size() -> Tuple[int, int]:
    data = _call_cua(["screen-size"])
    return (int(data.get("width", 0)), int(data.get("height", 0)))

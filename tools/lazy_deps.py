"""Lazy dependency installer — installs optional packages on first use."""

from __future__ import annotations

import logging
import subprocess
import sys
from typing import List, Optional

logger = logging.getLogger(__name__)


def ensure_installed(
    packages: List[str],
    *,
    quiet: bool = True,
    timeout: int = 120,
) -> bool:
    """Ensure *packages* are installed; install them if not.

    Returns True if all packages are importable after this call.
    """
    to_install = []
    for pkg in packages:
        # Try the bare module name (strip version specifiers)
        mod = pkg.split(">=")[0].split("==")[0].split("[")[0].strip()
        try:
            __import__(mod)
        except ImportError:
            to_install.append(pkg)

    if not to_install:
        return True

    import shutil
    uv = shutil.which("uv")
    pip_cmd = (
        [uv, "pip", "install"] if uv
        else [sys.executable, "-m", "pip", "install"]
    )
    if quiet:
        pip_cmd.append("--quiet")

    try:
        result = subprocess.run(
            pip_cmd + to_install,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0
    except Exception as exc:
        logger.debug("lazy_deps install failed: %s", exc)
        return False


def ensure_pyautogui() -> bool:
    """Ensure pyautogui + Pillow are installed."""
    return ensure_installed(["pyautogui", "pillow"])

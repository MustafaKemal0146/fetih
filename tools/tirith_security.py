"""Tirith security scanner — stub module.

Pattern-matching security scanner for shell commands.
The full scanner binary is optional; this stub provides a graceful fallback.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_RISKY_PATTERNS = [
    re.compile(r"curl\s+[^|]*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"wget\s+[^|]*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"\brm\s+-[rf]{1,3}\s+/[^\s]*", re.IGNORECASE),
    re.compile(r":()\{:\|:&\}", re.IGNORECASE),
    re.compile(r"\bsudo\s+rm\s+-[rf]", re.IGNORECASE),
    re.compile(r"\bdd\s+if=.*of=/dev/(sd|nvme|hd)", re.IGNORECASE),
    re.compile(r"\bmkfs\.", re.IGNORECASE),
]


def is_platform_supported() -> bool:
    return sys.platform in ("linux", "darwin")


def ensure_installed(log_failures: bool = True) -> Optional[str]:
    """Return the path to the tirith binary if available, else None."""
    import shutil
    return shutil.which("tirith")


def scan_command(command: str) -> Optional[str]:
    """Return a risk description string if the command looks dangerous, else None."""
    for pat in _RISKY_PATTERNS:
        if pat.search(command):
            return f"Pattern match: {pat.pattern[:60]}"
    return None

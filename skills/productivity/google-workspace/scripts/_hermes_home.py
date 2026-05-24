"""Resolve FETIH_HOME for standalone skill scripts.

Skill scripts may run outside the FETIH process (e.g. system Python,
nix env, CI) where ``fetih_constants`` is not importable.  This module
provides the same ``get_fetih_home()`` and ``display_fetih_home()``
contracts as ``fetih_constants`` without requiring it on ``sys.path``.

When ``fetih_constants`` IS available it is used directly so that any
future enhancements (profile resolution, Docker detection, etc.) are
picked up automatically.  The fallback path replicates the core logic
from ``fetih_constants.py`` using only the stdlib.

All scripts under ``google-workspace/scripts/`` should import from here
instead of duplicating the ``FETIH_HOME = Path(os.getenv(...))`` pattern.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from fetih_constants import display_fetih_home as display_fetih_home
    from fetih_constants import get_fetih_home as get_fetih_home
except (ModuleNotFoundError, ImportError):

    def get_fetih_home() -> Path:
        """Return the FETIH home directory (default: ~/.fetih).

        Mirrors ``fetih_constants.get_fetih_home()``."""
        val = os.environ.get("FETIH_HOME", "").strip()
        return Path(val) if val else Path.home() / ".fetih"

    def display_fetih_home() -> str:
        """Return a user-friendly ``~/``-shortened display string.

        Mirrors ``fetih_constants.display_fetih_home()``."""
        home = get_fetih_home()
        try:
            return "~/" + str(home.relative_to(Path.home()))
        except ValueError:
            return str(home)

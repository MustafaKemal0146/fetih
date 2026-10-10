"""Workspace management for FETİH desktop bridge.

Controls the active workspace path and sandboxing writes within that workspace
via FETIH_WRITE_SAFE_ROOT.
"""

from __future__ import annotations

import os
from typing import Optional


_current_workspace: Optional[str] = None


def current_workspace() -> Optional[str]:
    """Return the currently active workspace directory."""
    global _current_workspace
    if _current_workspace:
        return _current_workspace
    safe_root = os.getenv("FETIH_WRITE_SAFE_ROOT")
    return safe_root or None


def apply_workspace(path: str, restrict: Optional[bool] = None) -> str:
    """Set the active workspace and optionally restrict writes to it.

    If restrict is None, reads config 'desktop.restrict_to_workspace' (defaults to True).
    Normalizes the path with realpath and sets FETIH_WRITE_SAFE_ROOT if restrict is True.
    """
    global _current_workspace
    if not path:
        return ""

    p_str = str(path)
    if len(p_str) >= 3 and p_str[0] == "/" and p_str[2] == "/" and p_str[1].isalpha():
        p_str = f"{p_str[1].upper()}:{p_str[2:]}"
    norm = os.path.normcase(os.path.realpath(os.path.expanduser(p_str)))
    _current_workspace = norm

    if restrict is None:
        try:
            from fetih_cli.config import load_config

            cfg = load_config()
            desktop_cfg = cfg.get("desktop") or {}
            restrict = bool(desktop_cfg.get("restrict_to_workspace", True))
        except Exception:
            restrict = True

    if restrict:
        os.environ["FETIH_WRITE_SAFE_ROOT"] = norm
    return norm


def reset_workspace() -> None:
    """Clear workspace tracking (mainly for test cleanup)."""
    global _current_workspace
    _current_workspace = None

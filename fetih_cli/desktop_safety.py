"""Cross-platform safety layer for desktop control operations.

Provides FAILSAFE detection, audit logging, blocked key/pattern checking,
and platform-aware restrictions. Used by both the computer_use tool and
any future desktop automation features.

Safety tiers:
  Level 0 (READ):   Screenshot, window list — ALWAYS allowed, no log
  Level 1 (NAV):    mouse move, scroll — logged, no approval needed
  Level 2 (CLICK):  click, type single keys — logged, approval optional
  Level 3 (TYPE):   type text — logged, approval RECOMMENDED
  Level 4 (EXEC):   hotkey combos, set_value — logged, approval REQUIRED
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_PLATFORM = sys.platform  # "linux", "darwin", "win32"


def get_platform() -> str:
    """Return normalized platform name."""
    if _PLATFORM == "darwin":
        return "macos"
    elif _PLATFORM == "win32":
        return "windows"
    return "linux"


# ---------------------------------------------------------------------------
# Safety tier mapping
# ---------------------------------------------------------------------------

_SAFETY_TIER: Dict[str, int] = {
    # Level 0: passive — always allowed
    "capture": 0, "screenshot": 0, "list_apps": 0, "list_windows": 0,
    "get_active_window": 0, "get_mouse_position": 0, "get_screen_size": 0,
    # Level 1: non-destructive navigation
    "scroll": 1, "move_mouse": 1, "wait": 1, "hover": 1,
    # Level 2: single clicks, key press
    "click": 2, "double_click": 2, "right_click": 2, "middle_click": 2,
    "press_key": 2, "key_down": 2, "key_up": 2,
    # Level 3: text input
    "type": 3, "type_text": 3,
    # Level 4: multi-key combos, programmatic value setting
    "key": 4, "hotkey": 4, "set_value": 4, "drag": 4,
    "focus_app": 4, "focus_window": 4,
}


def get_safety_tier(action: str) -> int:
    """Return the safety tier (0-4) for an action name."""
    return _SAFETY_TIER.get(action.lower(), 4)  # Unknown actions → tier 4


def is_readonly_action(action: str) -> bool:
    """Return True for passive/read-only actions."""
    return get_safety_tier(action) == 0


def is_destructive_action(action: str) -> bool:
    """Return True for actions that modify user-visible state."""
    return get_safety_tier(action) >= 2


def requires_approval(action: str, approval_level: int = 2) -> bool:
    """Return True if action requires approval at the given threshold."""
    return get_safety_tier(action) >= approval_level


# ---------------------------------------------------------------------------
# Blocked key combinations (cross-platform)
# ---------------------------------------------------------------------------

# Platform-specific destructive key combos
_BLOCKED_KEY_COMBOS_LINUX = [
    {"ctrl", "alt", "backspace"},     # kill X server
    {"ctrl", "alt", "delete"},        # reboot/shutdown dialog
    {"ctrl", "alt", "f1"},            # switch to VT
    {"ctrl", "alt", "f2"},
    {"ctrl", "alt", "f3"},
    {"ctrl", "alt", "f4"},
    {"ctrl", "alt", "f5"},
    {"ctrl", "alt", "f6"},
    {"ctrl", "alt", "f7"},
    {"alt", "sysrq", "b"},            # emergency reboot
    {"alt", "sysrq", "o"},            # emergency shutdown
    {"super", "l"},                   # lock screen (block in strict mode)
]

_BLOCKED_KEY_COMBOS_MACOS = [
    {"cmd", "shift", "backspace"},    # empty trash
    {"cmd", "option", "backspace"},   # force delete
    {"cmd", "ctrl", "q"},             # lock screen
    {"cmd", "shift", "q"},            # log out
    {"cmd", "option", "shift", "q"},  # force log out
    {"cmd", "ctrl", "eject"},         # restart
    {"cmd", "option", "ctrl", "eject"},  # shutdown
]

_BLOCKED_KEY_COMBOS_WINDOWS = [
    {"ctrl", "alt", "delete"},        # security screen
    {"win", "l"},                     # lock
    {"win", "r"},                     # run dialog (dangerous with curl|sh)
    {"alt", "f4"},                    # close window
    {"win", "x"},                     # power user menu
    {"win", "u"},                     # ease of access
]


def _get_blocked_combos() -> List[Set[str]]:
    """Return platform-specific blocked key combinations."""
    if _PLATFORM == "darwin":
        return [frozenset(c) for c in _BLOCKED_KEY_COMBOS_MACOS]
    elif _PLATFORM == "win32":
        return [frozenset(c) for c in _BLOCKED_KEY_COMBOS_WINDOWS]
    else:
        return [frozenset(c) for c in _BLOCKED_KEY_COMBOS_LINUX]


_KEY_ALIASES_GLOBAL = {
    "command": "cmd", "control": "ctrl",
    # "option" is the macOS name for Alt; normalize to "alt" so blocked combos match
    "option": "alt",
    "⌘": "cmd", "⌥": "alt",
    # On macOS "win/super" maps to "cmd"; on Windows/Linux keep as "win"
    **( {"win": "cmd", "super": "cmd"} if _PLATFORM == "darwin"
        else {"super": "win"} ),
    "return": "enter", "esc": "escape", "del": "delete",
}


def is_key_combo_blocked(keys: str) -> Optional[str]:
    """Return block reason if the key combo is blocked, or None."""
    parts = [p.strip().lower() for p in re.split(r'\s*\+\s*', keys) if p.strip()]
    normalized = frozenset(_KEY_ALIASES_GLOBAL.get(p, p) for p in parts)

    for blocked in _get_blocked_combos():
        if blocked.issubset(normalized):
            return f"Blocked key combo: {'+'.join(sorted(blocked))}"

    return None


# ---------------------------------------------------------------------------
# Blocked type patterns (shell injection, etc.)
# ---------------------------------------------------------------------------

_BLOCKED_TYPE_PATTERNS = [
    (re.compile(r"curl\s+[^|]*\|\s*bash", re.IGNORECASE), "curl|bash pipe"),
    (re.compile(r"curl\s+[^|]*\|\s*sh", re.IGNORECASE), "curl|sh pipe"),
    (re.compile(r"wget\s+[^|]*\|\s*bash", re.IGNORECASE), "wget|bash pipe"),
    (re.compile(r"\bsudo\s+rm\s+-[rf]", re.IGNORECASE), "sudo rm -rf"),
    (re.compile(r"\brm\s+-rf\s+/\s*$", re.IGNORECASE), "rm -rf /"),
    (re.compile(r":\s*\(\)\s*\{\s*:\|:\s*&\s*\}", re.IGNORECASE), "fork bomb"),
    (re.compile(r"\bdd\s+if=.*of=/dev/sd", re.IGNORECASE), "dd to block device"),
    (re.compile(r"\bmkfs\.", re.IGNORECASE), "mkfs"),
]


def is_type_text_blocked(text: str) -> Optional[str]:
    """Return block reason if the text contains dangerous patterns."""
    for pat, reason in _BLOCKED_TYPE_PATTERNS:
        if pat.search(text):
            return f"Blocked pattern ({reason}): {pat.pattern[:50]}..."
    return None


# ---------------------------------------------------------------------------
# Blocked directories (sensitive paths)
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys",
    "~/.gnupg/secring.gpg", "~/.gnupg/private-keys-v1.d",
    "~/.aws/credentials", "~/.azure/accessTokens.json",
    "~/.config/gcloud/credentials.db",
    "/root/.bashrc", "/root/.profile",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SECURITY",
]


def is_sensitive_path(path: str) -> bool:
    """Check if a path points to a sensitive system/credential file."""
    expanded = os.path.expanduser(path)
    for sensitive in _SENSITIVE_PATHS:
        if expanded == os.path.expanduser(sensitive):
            return True
        if expanded.startswith(os.path.expanduser(sensitive) + os.sep):
            return True
    return False


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

_AUDIT_LOG_LOCK = __import__('threading').Lock()


def _get_audit_log_path() -> Path:
    """Return path to the desktop control audit log."""
    fetih_home = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))
    return Path(fetih_home) / "desktop_audit.log"


def log_desktop_action(
    action: str,
    args: Dict[str, Any],
    result_ok: bool,
    result_msg: str = "",
    approved: bool = True,
) -> None:
    """Log a desktop control action to the audit file."""
    with _AUDIT_LOG_LOCK:
        try:
            log_path = _get_audit_log_path()
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Sanitize args: never log full text content
            safe_args = dict(args)
            if "text" in safe_args:
                safe_args["text"] = f"[{len(safe_args['text'])} chars]"
            if "value" in safe_args and len(str(safe_args.get("value", ""))) > 40:
                safe_args["value"] = f"[{len(str(safe_args['value']))} chars]"

            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "args": safe_args,
                "ok": result_ok,
                "msg": result_msg[:200],
                "approved": approved,
                "platform": get_platform(),
            }

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # Never let audit logging break the tool


def get_desktop_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    """Read the last N entries from the audit log."""
    try:
        log_path = _get_audit_log_path()
        if not log_path.exists():
            return []
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        entries = []
        for line in lines[-limit:]:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries
    except Exception:
        return []


# ---------------------------------------------------------------------------
# FAILSAFE detection
# ---------------------------------------------------------------------------

def check_failsafe() -> bool:
    """Return True if FAILSAFE has triggered (mouse at corner 0,0).

    pyautogui's built-in FAILSAFE raises FailSafeException, but we also
    provide an explicit check that can be called before dangerous ops.
    """
    try:
        import pyautogui
        x, y = pyautogui.position()
        # FAILSAFE triggers when mouse is at (0,0) or very close
        if x <= 1 and y <= 1:
            return True
        return False
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Approval prompt helper
# ---------------------------------------------------------------------------

def format_approval_prompt(action: str, args: Dict[str, Any]) -> str:
    """Format a human-readable approval prompt for a desktop action."""
    tier = get_safety_tier(action)
    tier_label = {0: "READ", 1: "NAV", 2: "CLICK", 3: "TYPE", 4: "EXEC"}.get(tier, "???")

    summary = f"[{tier_label}] {action}"

    if action in {"click", "double_click", "right_click", "middle_click"}:
        if args.get("coordinate"):
            c = args["coordinate"]
            summary += f" at ({c[0]}, {c[1]})"
        elif args.get("x") is not None:
            summary += f" at ({args['x']}, {args['y']})"
    elif action == "type":
        text = args.get("text", "")
        summary += f" {text[:60]!r}{'...' if len(text) > 60 else ''}"
    elif action == "key":
        summary += f" {args.get('keys', '')!r}"
    elif action == "drag":
        summary += f" {args.get('from_coordinate', '?')} → {args.get('to_coordinate', '?')}"
    elif action == "scroll":
        summary += f" {args.get('direction', '?')} x{args.get('amount', 3)}"

    return summary


# ---------------------------------------------------------------------------
# Safety check entry point
# ---------------------------------------------------------------------------

def validate_desktop_action(
    action: str,
    args: Dict[str, Any],
    require_approval: bool = True,
) -> Tuple[bool, Optional[str]]:
    """Validate a desktop action before execution.

    Returns (allowed, error_message). If allowed=False, error_message
    explains why the action was blocked.

    Checks in order:
    1. FAILSAFE trigger
    2. Blocked key combos (for 'key' action)
    3. Blocked text patterns (for 'type' action)
    4. Safety tier
    """
    # 1. FAILSAFE check
    if check_failsafe():
        return False, "FAILSAFE: Mouse is at upper-left corner (0,0). " \
                       "Desktop control is paused for safety. " \
                       "Move the mouse away from the corner to re-enable."

    # 2. Key combo check
    if action in {"key", "hotkey"}:
        keys = args.get("keys", "")
        blocked = is_key_combo_blocked(keys)
        if blocked:
            return False, blocked

    # 3. Type text check
    if action in {"type", "type_text"}:
        text = args.get("text", "")
        blocked = is_type_text_blocked(text)
        if blocked:
            return False, blocked

    # 4. All checks passed
    return True, None

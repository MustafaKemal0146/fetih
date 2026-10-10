"""User-defined tool permission rules (allow / ask / deny).

Supports per-tool rules with glob matching on command/path subjects.
Rule format in config.yaml:
permissions:
  default: ask   # allow | ask | deny
  rules:
    - {tool: terminal, match: "git *", action: allow}
    - {tool: terminal, match: "rm *", action: deny}
    - {tool: write_file, match: "*", action: ask}
"""

from __future__ import annotations

import fnmatch
import logging
import os
import sys
from typing import Any, List, Literal, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)

PermissionAction = Literal["allow", "ask", "deny"]
VALID_ACTIONS: set[str] = {"allow", "ask", "deny"}


def load_rules(config: Mapping[str, Any] | None = None) -> Tuple[PermissionAction, List[dict]]:
    """Parse permissions configuration safely.

    Returns (default_action, list_of_rules).
    If config is None, attempts to load via `fetih_cli.config.load_config()`.
    If config is corrupt or invalid, logs a warning and returns ("ask", []).
    """
    if config is None:
        try:
            from fetih_cli.config import load_config
            config = load_config()
        except Exception as e:
            logger.warning("Failed to load config for permission rules: %s", e)
            return "ask", []

    if not isinstance(config, Mapping):
        return "ask", []

    perm_section = config.get("permissions")
    if perm_section is None:
        return "ask", []

    if not isinstance(perm_section, Mapping):
        logger.warning("Invalid 'permissions' section in config; must be a dict/mapping")
        return "ask", []

    raw_default = str(perm_section.get("default", "ask")).strip().lower()
    default_action: PermissionAction = raw_default if raw_default in VALID_ACTIONS else "ask"

    raw_rules = perm_section.get("rules")
    if raw_rules is None:
        return default_action, []

    if not isinstance(raw_rules, list):
        logger.warning("Invalid 'permissions.rules' in config; must be a list")
        return default_action, []

    valid_rules: List[dict] = []
    for item in raw_rules:
        if not isinstance(item, Mapping):
            continue
        tool = str(item.get("tool", "*")).strip()
        pattern = str(item.get("match", item.get("pattern", "*"))).strip()
        action = str(item.get("action", "")).strip().lower()
        if action not in VALID_ACTIONS:
            continue
        valid_rules.append({
            "tool": tool,
            "match": pattern,
            "action": action,
        })

    return default_action, valid_rules


def _is_windows() -> bool:
    return sys.platform == "win32" or os.name == "nt"


def _normalize_subject(tool: str, subject: str) -> str:
    """Normalize subject string for comparison (expand vars, tilde, and handle case)."""
    sub = str(subject).strip()
    if tool in {"write_file", "patch", "read_file", "file"}:
        sub = os.path.expanduser(sub)
        sub = os.path.expandvars(sub)
        sub = os.path.normpath(sub)
    if _is_windows():
        sub = sub.lower()
    return sub


def _normalize_pattern(tool: str, pattern: str) -> str:
    pat = str(pattern).strip()
    if tool in {"write_file", "patch", "read_file", "file"}:
        pat = os.path.expanduser(pat)
        pat = os.path.expandvars(pat)
        pat = os.path.normpath(pat)
    if _is_windows():
        pat = pat.lower()
    return pat


def evaluate(
    tool: str,
    subject: str,
    config: Mapping[str, Any] | None = None,
) -> PermissionAction:
    """Evaluate permission for a tool and subject against configured rules.

    Last matching rule wins. If no rule matches, returns default action.
    """
    action, _ = evaluate_rule_match(tool, subject, config)
    return action


def evaluate_rule_match(
    tool: str,
    subject: str,
    config: Mapping[str, Any] | None = None,
) -> Tuple[PermissionAction, Optional[dict]]:
    """Evaluate and return (action, winning_rule_dict).

    Last matching rule wins. If no rule matches, returns (default_action, None).
    """
    default_action, rules = load_rules(config)

    tool_norm = tool.strip().lower()
    subject_norm = _normalize_subject(tool_norm, subject)

    winning_rule: Optional[dict] = None

    for rule in rules:
        rule_tool = rule["tool"].strip().lower()
        if rule_tool != "*" and rule_tool != tool_norm:
            continue

        rule_match = _normalize_pattern(rule_tool, rule["match"])

        # Match glob pattern
        if rule_match == "*" or fnmatch.fnmatch(subject_norm, rule_match):
            winning_rule = rule

    if winning_rule is not None:
        return winning_rule["action"], winning_rule

    return default_action, None

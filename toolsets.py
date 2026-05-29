"""Toolset registry — maps toolset names to lists of tool names.

A toolset groups related tools. ``resolve_toolset`` expands a toolset
name (possibly composite) into the flat list of individual tool names
that get registered with the model.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Toolset definitions
# ---------------------------------------------------------------------------

TOOLSETS: Dict[str, Dict[str, Any]] = {
    # ── Core desktop / computer-use ────────────────────────────────────────
    "computer_use": {
        "tools": ["computer_use"],
        "description": "Cross-platform desktop control (screenshot, click, type, scroll, key)",
    },
    # ── File operations ────────────────────────────────────────────────────
    "file": {
        "tools": ["read_file", "write_file", "patch", "search_files"],
        "description": "Read, write, patch, and search files",
    },
    # ── Web search & extraction ────────────────────────────────────────────
    "web": {
        "tools": ["web_search", "web_extract"],
        "description": "Web search and page extraction",
    },
    # ── Terminal execution ─────────────────────────────────────────────────
    "terminal": {
        "tools": ["terminal"],
        "description": "Run shell commands",
    },
    # ── Code execution ─────────────────────────────────────────────────────
    "code_execution": {
        "tools": ["execute_code"],
        "description": "Execute sandboxed code",
    },
    # ── Vision ─────────────────────────────────────────────────────────────
    "vision": {
        "tools": ["vision_analyze"],
        "description": "Analyze images with vision model",
    },
    # ── Browser automation ─────────────────────────────────────────────────
    "browser": {
        "tools": ["navigate", "browser_click", "browser_type", "browser_scroll"],
        "description": "Automate browser actions",
    },
    # ── Memory ─────────────────────────────────────────────────────────────
    "memory": {
        "tools": ["memory_read", "memory_write", "memory_search"],
        "description": "Persistent memory across sessions",
    },
    # ── Task planning ──────────────────────────────────────────────────────
    "todo": {
        "tools": ["todo_read", "todo_write"],
        "description": "Read/write task lists",
    },
    # ── Delegation ─────────────────────────────────────────────────────────
    "delegation": {
        "tools": ["delegate_task"],
        "description": "Spawn sub-agents for parallel work",
    },
    # ── Skills management ──────────────────────────────────────────────────
    "skills": {
        "tools": ["skills_list", "skill_view"],
        "description": "List and view agent skills",
    },
    # ── Clarification ──────────────────────────────────────────────────────
    "clarify": {
        "tools": ["clarify"],
        "description": "Ask clarifying questions",
    },
    # ── Session search ─────────────────────────────────────────────────────
    "session_search": {
        "tools": ["session_search"],
        "description": "Search past conversation sessions",
    },
    # ── Composite / meta toolsets ──────────────────────────────────────────
    "fetih-cli": {
        "includes": [
            "file", "terminal", "web", "code_execution",
            "vision", "browser", "memory", "todo",
            "delegation", "skills", "clarify", "session_search",
            "computer_use",
        ],
        "description": "Full FETIH CLI toolset",
    },
    "fetih-telegram": {
        "includes": [
            "file", "web", "code_execution", "vision",
            "memory", "todo", "delegation", "skills",
        ],
        "description": "FETIH Telegram gateway toolset",
    },
    "fetih-discord": {
        "includes": [
            "file", "web", "code_execution", "vision",
            "memory", "todo", "delegation", "skills",
        ],
        "description": "FETIH Discord gateway toolset",
    },
    "fetih-slack": {
        "includes": [
            "file", "web", "code_execution", "vision",
            "memory", "todo", "delegation", "skills",
        ],
        "description": "FETIH Slack gateway toolset",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_toolset(name: str) -> List[str]:
    """Return the flat list of tool names for a toolset (expands includes)."""
    ts = TOOLSETS.get(name)
    if not ts:
        return []
    tools = list(ts.get("tools", []))
    for inc in ts.get("includes", []):
        for tool in resolve_toolset(inc):
            if tool not in tools:
                tools.append(tool)
    return tools


def resolve_multiple_toolsets(names: List[str]) -> List[str]:
    """Resolve multiple toolsets and return deduplicated tool names."""
    seen: set[str] = set()
    result: List[str] = []
    for name in names:
        for tool in resolve_toolset(name):
            if tool not in seen:
                seen.add(tool)
                result.append(tool)
    return result


def get_toolset(name: str) -> Optional[Dict[str, Any]]:
    """Return the raw toolset dict for *name*, or None."""
    return TOOLSETS.get(name)


def get_toolset_info(name: str) -> Dict[str, Any]:
    """Return info dict for *name* (empty dict if not found)."""
    ts = TOOLSETS.get(name)
    if not ts:
        return {}
    return {
        "name": name,
        "tools": resolve_toolset(name),
        "description": ts.get("description", ""),
    }


def get_all_toolsets() -> List[str]:
    """Return all registered toolset names."""
    return list(TOOLSETS.keys())


def get_toolset_names() -> List[str]:
    """Alias for get_all_toolsets()."""
    return get_all_toolsets()


def validate_toolset(name: str) -> bool:
    """Return True if *name* is a known toolset."""
    return name in TOOLSETS

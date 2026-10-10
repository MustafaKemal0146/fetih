#!/usr/bin/env python3
"""
Capability Map and use_tool Bridge (#75 Faz 1-3)

Provides:
- use_tool(name, arguments): A single unified bridge to execute extended tools
  from the capability map without bloating top-level prompt context schemas.
- Wire-to-canonical tool name normalization (e.g. bash -> terminal, str_replace_editor -> patch).
- Groq tool_use_failed / JSON string argument recovery.
- Hierarchical capability map generation for tools and skills.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from tools.registry import registry

logger = logging.getLogger(__name__)

# Common model wire aliases mapped to native FETIH tool names
WIRE_TOOL_ALIASES: Dict[str, str] = {
    "bash": "terminal",
    "sh": "terminal",
    "shell": "terminal",
    "cmd": "terminal",
    "exec": "terminal",
    "command": "terminal",
    "str_replace_editor": "patch",
    "edit": "patch",
    "edit_file": "patch",
    "view": "read_file",
    "cat": "read_file",
    "create": "write_file",
    "save": "write_file",
    "search": "search_files",
    "find": "search_files",
    "grep": "search_files",
    "run_python": "execute_code",
    "python": "execute_code",
    "google": "web_search",
    "search_web": "web_search",
    "skills": "skills_list",
}


def normalize_tool_name(name: str) -> str:
    """Normalize wire / alias tool names to canonical FETIH registry names."""
    if not name:
        return ""
    clean = str(name).strip().lower().replace("-", "_")
    return WIRE_TOOL_ALIASES.get(clean, clean)


def parse_tool_arguments(raw_args: Any) -> Dict[str, Any]:
    """Recover tool arguments from dict, JSON string, or Groq failure format."""
    if raw_args is None:
        return {}
    if isinstance(raw_args, dict):
        # Groq / provider wrapped failure: {"tool_use_failed": ...}
        if "tool_use_failed" in raw_args:
            failed_val = raw_args["tool_use_failed"]
            if isinstance(failed_val, dict):
                return failed_val
            if isinstance(failed_val, str):
                try:
                    parsed = json.loads(failed_val)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass
        return raw_args

    if isinstance(raw_args, str):
        trimmed = raw_args.strip()
        if not trimmed:
            return {}
        try:
            parsed = json.loads(trimmed)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            # Maybe argument was passed as a single string parameter
            return {"command": trimmed}

    return {"value": raw_args}


def use_tool(
    name: str,
    arguments: Any = None,
    task_id: Optional[str] = None,
    **kwargs: Any,
) -> str:
    """Execute an extended tool by name and arguments.

    Handles wire aliases, string-encoded arguments, and routes directly
    through model_tools.handle_function_call.
    """
    if not name:
        return json.dumps({"error": "use_tool requires a valid tool 'name'"}, ensure_ascii=False)

    canonical_name = normalize_tool_name(name)
    parsed_args = parse_tool_arguments(arguments)

    # Disallow recursion
    if canonical_name == "use_tool":
        nested_name = parsed_args.get("name") or parsed_args.get("tool_name", "")
        if not nested_name or normalize_tool_name(nested_name) == "use_tool":
            return json.dumps({"error": "Recursive use_tool call is not permitted"}, ensure_ascii=False)
        nested_args = parsed_args.get("arguments") or parsed_args.get("args", {})
        return use_tool(nested_name, nested_args, task_id=task_id, **kwargs)

    try:
        from model_tools import handle_function_call

        return handle_function_call(
            function_name=canonical_name,
            function_args=parsed_args,
            task_id=task_id,
            **kwargs,
        )
    except Exception as exc:
        logger.exception("use_tool dispatch failed for %s: %s", canonical_name, exc)
        return json.dumps(
            {"error": f"Failed to execute tool '{canonical_name}': {type(exc).__name__}: {exc}"},
            ensure_ascii=False,
        )


def build_capability_map(
    tools: Optional[List[str]] = None,
    quiet: bool = True,
) -> Dict[str, Any]:
    """Build a structured capability map for tools and categories.

    Returns:
        Dict with total count, categorized tool summaries, and wire aliases.
    """
    if tools is None:
        if len(registry.get_all_tool_names()) <= 1:
            from tools.registry import discover_builtin_tools
            discover_builtin_tools()
        target_tools = set(registry.get_all_tool_names())
    else:
        target_tools = set(tools)

    tool_to_set = registry.get_tool_to_toolset_map()
    defs = registry.get_definitions(tool_names=target_tools, quiet=quiet)
    by_category: Dict[str, List[Dict[str, str]]] = {}

    for t in defs:
        fn = t.get("function") or {}
        name = fn.get("name", "")
        if not name or name == "use_tool":
            continue
        desc = (fn.get("description") or "").split("\n")[0][:120]
        cat = tool_to_set.get(name, "other")
        by_category.setdefault(cat, []).append({
            "name": name,
            "description": desc,
        })

    return {
        "total": sum(len(v) for v in by_category.values()),
        "categories": {cat: {"count": len(items), "tools": items} for cat, items in sorted(by_category.items())},
        "aliases": WIRE_TOOL_ALIASES,
    }


# Register use_tool in capability_map toolset
registry.register(
    name="use_tool",
    toolset="capability_map",
    schema={
        "name": "use_tool",
        "description": "Execute an extended tool from the capability map by providing its name and argument dictionary.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name of the tool to execute from the capability map (e.g. 'web_search', 'terminal', 'read_file')",
                },
                "arguments": {
                    "type": "object",
                    "description": "Arguments dictionary to pass to the tool",
                },
            },
            "required": ["name"],
        },
    },
    handler=lambda args, **kw: use_tool(
        name=args.get("name") or args.get("tool_name", ""),
        arguments=args.get("arguments") or args.get("args", {}),
        task_id=kw.get("task_id"),
    ),
)

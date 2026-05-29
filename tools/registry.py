"""Tool registry — central hub for tool registration and dispatch.

Each tool module self-registers via registry.register() at import time.
``discover_builtin_tools()`` triggers discovery by importing every module
in the ``tools/`` package.

Public surface:
    registry          — the singleton Registry instance
    discover_builtin_tools()
    tool_error(msg)   — format an error result string
    tool_result(data) — format a success result string
    invalidate_check_fn_cache()
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import logging
import pkgutil
import threading
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def tool_error(message: str) -> str:
    """Return a JSON-serialised tool error string."""
    return json.dumps({"error": message}, ensure_ascii=False)


def tool_result(data: Any) -> str:
    """Return a JSON-serialised tool result string."""
    if isinstance(data, str):
        return data
    return json.dumps(data, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class _Registry:
    """Singleton registry for all tool definitions, handlers and metadata."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tools: Dict[str, Dict] = {}
        self._handlers: Dict[str, Callable] = {}
        self._check_fns: Dict[str, Callable] = {}
        self._toolsets: Dict[str, List[str]] = {}
        self._check_fn_cache: Dict[str, bool] = {}

    # ── Registration ────────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        schema: Dict,
        handler: Callable,
        toolset: str = "computer_use",
        check_fn: Optional[Callable] = None,
        **kwargs: Any,
    ) -> None:
        """Register a tool with its JSON schema and Python handler."""
        with self._lock:
            self._tools[name] = schema
            self._handlers[name] = handler
            if check_fn is not None:
                self._check_fns[name] = check_fn
            self._toolsets.setdefault(toolset, [])
            if name not in self._toolsets[toolset]:
                self._toolsets[toolset].append(name)

    # ── Lookup ──────────────────────────────────────────────────────────────

    def get_schema(self, name: str) -> Optional[Dict]:
        return self._tools.get(name)

    def get_all_tool_names(self) -> List[str]:
        return list(self._tools.keys())

    def get_handler(self, name: str) -> Optional[Callable]:
        return self._handlers.get(name)

    def get_toolset_tools(self, toolset: str) -> List[str]:
        return list(self._toolsets.get(toolset, []))

    def get_tool_to_toolset_map(self) -> Dict[str, str]:
        """Return {tool_name: toolset_name} for every registered tool."""
        with self._lock:
            result: Dict[str, str] = {}
            for toolset, tools in self._toolsets.items():
                for tool in tools:
                    result[tool] = toolset
            return result

    def get_toolset_requirements(self) -> Dict[str, dict]:
        """Return {toolset_name: {"name": ..., "tools": [...]}} for all toolsets."""
        with self._lock:
            return {
                toolset: {"name": toolset, "tools": list(tools)}
                for toolset, tools in self._toolsets.items()
            }

    def is_tool_available(self, name: str) -> bool:
        """Return True when the tool is registered and its check_fn passes."""
        if name not in self._tools:
            return False
        check_fn = self._check_fns.get(name)
        if check_fn is None:
            return True
        cached = self._check_fn_cache.get(name)
        if cached is not None:
            return cached
        try:
            result = bool(check_fn())
        except Exception:
            result = False
        self._check_fn_cache[name] = result
        return result

    # ── Dispatch ────────────────────────────────────────────────────────────

    def dispatch(self, name: str, args: Dict[str, Any]) -> str:
        """Synchronously dispatch a tool call and return the result string."""
        handler = self._handlers.get(name)
        if handler is None:
            return tool_error(f"Unknown tool: {name}")
        try:
            if inspect.iscoroutinefunction(handler):
                result = _run_async_in_thread(handler(**args))
            else:
                result = handler(**args)
            if result is None:
                return ""
            if isinstance(result, str):
                return result
            return json.dumps(result, ensure_ascii=False)
        except Exception as exc:
            logger.exception("Tool %s failed", name)
            return tool_error(str(exc))


def _run_async_in_thread(coro) -> Any:
    """Run a coroutine from a sync context via a dedicated thread loop."""
    result_box: list = [None]
    exc_box: list = [None]

    def _run():
        loop = asyncio.new_event_loop()
        try:
            result_box[0] = loop.run_until_complete(coro)
        except Exception as e:
            exc_box[0] = e
        finally:
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join()
    if exc_box[0] is not None:
        raise exc_box[0]
    return result_box[0]


# Singleton
registry = _Registry()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

_discovery_done = False
_discovery_lock = threading.Lock()


def discover_builtin_tools() -> None:
    """Import all tool submodules so they self-register with the registry."""
    global _discovery_done
    with _discovery_lock:
        if _discovery_done:
            return
        _discovery_done = True

    import tools as _tools_pkg

    skipped = {"registry", "lazy_deps", "skill_usage", "approval",
               "ansi_strip", "binary_extensions", "budget_config",
               "credential_files", "debug_helpers", "env_passthrough",
               "file_safety", "file_state", "fuzzy_match",
               "managed_tool_gateway", "mcp_oauth", "mcp_oauth_manager",
               "osv_check", "patch_parser", "path_security",
               "process_registry", "schema_sanitizer", "skill_provenance",
               "skill_usage", "skills_guard", "slash_confirm",
               "tool_backend_helpers", "tool_output_limits",
               "tool_result_storage", "url_safety", "website_policy",
               "neutts_synth", "openrouter_client", "xai_http",
               "tirith_security", "clarify_gateway"}

    for importer, modname, ispkg in pkgutil.iter_modules(_tools_pkg.__path__):
        if modname.startswith("_") or modname in skipped:
            continue
        try:
            importlib.import_module(f"tools.{modname}")
        except Exception as exc:
            logger.debug("Could not import tools.%s: %s", modname, exc)

    # Always try computer_use explicitly
    try:
        importlib.import_module("tools.computer_use.tool")
    except Exception as exc:
        logger.debug("Could not import tools.computer_use.tool: %s", exc)


def invalidate_check_fn_cache() -> None:
    """Clear the check_fn result cache so availability is re-evaluated."""
    registry._check_fn_cache.clear()

"""Agent lifecycle hooks system.

Provides a pluggable hook system for the FETIH agent lifecycle, inspired
by OpenClaw's agent-hooks architecture. Hooks can be registered by plugins,
built-in modules, or user scripts.

Hook points:
  on_session_start    — When a new session begins
  on_session_end      — When a session ends
  on_tool_start       — Before a tool executes
  on_tool_end         — After a tool returns (success or failure)
  on_compaction       — When context is compacted
  on_model_call       — Before/after each LLM API call
  on_error            — When an unhandled error occurs
  on_learn            — When a new learning is recorded

Each hook receives a HookContext with session info, timing, and metadata.

Usage:
  from fetih_cli.agent_hooks import register_hook, fire_hook

  def my_hook(ctx):
      print(f"Tool {ctx.tool_name} took {ctx.duration_ms}ms")

  register_hook("on_tool_end", my_hook)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hook context
# ---------------------------------------------------------------------------

@dataclass
class HookContext:
    """Context passed to every hook callback."""

    event: str                              # hook event name
    session_id: str = ""
    model: str = ""
    provider: str = ""
    timestamp: float = field(default_factory=time.time)

    # Tool-specific
    tool_name: str = ""
    tool_args: Dict[str, Any] = field(default_factory=dict)
    tool_result_ok: bool = True
    tool_result_summary: str = ""
    tool_duration_ms: float = 0.0

    # Compaction-specific
    tokens_before: int = 0
    tokens_after: int = 0
    compaction_reason: str = ""

    # Model call-specific
    model_request_tokens: int = 0
    model_response_tokens: int = 0
    model_duration_ms: float = 0.0
    model_finish_reason: str = ""

    # Error-specific
    error_type: str = ""
    error_message: str = ""
    error_traceback: str = ""

    # Learning-specific
    learning_id: str = ""
    learning_category: str = ""

    # Arbitrary extras
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event,
            "session_id": self.session_id,
            "model": self.model,
            "provider": self.provider,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "tool_result_ok": self.tool_result_ok,
            "tool_duration_ms": self.tool_duration_ms,
            "tokens_before": self.tokens_before,
            "tokens_after": self.tokens_after,
            "model_request_tokens": self.model_request_tokens,
            "model_response_tokens": self.model_response_tokens,
            "model_duration_ms": self.model_duration_ms,
            "error_type": self.error_type,
            "learning_id": self.learning_id,
        }


# ---------------------------------------------------------------------------
# Hook registry
# ---------------------------------------------------------------------------

HookCallback = Callable[[HookContext], None]

_registry: Dict[str, List[HookCallback]] = defaultdict(list)
_registry_lock = threading.Lock()

# Statistics collected by built-in hooks
_stats: Dict[str, Any] = {
    "sessions_started": 0,
    "sessions_ended": 0,
    "total_tool_calls": 0,
    "failed_tool_calls": 0,
    "total_model_calls": 0,
    "total_compactions": 0,
    "total_errors": 0,
    "tool_timing": defaultdict(list),       # tool_name → [duration_ms, ...]
    "model_timing": [],                      # [duration_ms, ...]
    "errors_by_type": defaultdict(int),
    "busy_tools": defaultdict(int),          # tool_name → call count
}
_stats_lock = threading.Lock()


def register_hook(event: str, callback: HookCallback) -> None:
    """Register a hook callback for a lifecycle event.

    Events:
      - on_session_start
      - on_session_end
      - on_tool_start
      - on_tool_end
      - on_compaction
      - on_model_call
      - on_error
      - on_learn
    """
    with _registry_lock:
        _registry[event].append(callback)
        logger.debug("Registered hook %s for event %s",
                     getattr(callback, '__name__', str(callback)), event)


def unregister_hook(event: str, callback: HookCallback) -> bool:
    """Remove a previously registered hook."""
    with _registry_lock:
        if callback in _registry[event]:
            _registry[event].remove(callback)
            return True
    return False


def fire_hook(event: str, ctx: Optional[HookContext] = None, **kwargs) -> None:
    """Fire all registered hooks for an event.

    Hooks are called synchronously in registration order. Exceptions in
    hooks are caught and logged — they never propagate to the caller.
    """
    if ctx is None:
        ctx = HookContext(event=event, **kwargs)
    else:
        ctx.event = event

    # Update built-in stats
    _update_stats(event, ctx)

    with _registry_lock:
        callbacks = list(_registry.get(event, []))

    for cb in callbacks:
        try:
            cb(ctx)
        except Exception as e:
            logger.warning("Hook %s/%s failed: %s",
                          event, getattr(cb, '__name__', str(cb)), e)


def _update_stats(event: str, ctx: HookContext) -> None:
    """Update internal statistics from hook events."""
    with _stats_lock:
        if event == "on_session_start":
            _stats["sessions_started"] += 1
        elif event == "on_session_end":
            _stats["sessions_ended"] += 1
        elif event == "on_tool_start":
            _stats["total_tool_calls"] += 1
            _stats["busy_tools"][ctx.tool_name] += 1
        elif event == "on_tool_end":
            if not ctx.tool_result_ok:
                _stats["failed_tool_calls"] += 1
            if ctx.tool_duration_ms > 0:
                _stats["tool_timing"][ctx.tool_name].append(ctx.tool_duration_ms)
        elif event == "on_model_call":
            _stats["total_model_calls"] += 1
            if ctx.model_duration_ms > 0:
                _stats["model_timing"].append(ctx.model_duration_ms)
        elif event == "on_compaction":
            _stats["total_compactions"] += 1
        elif event == "on_error":
            _stats["total_errors"] += 1
            _stats["errors_by_type"][ctx.error_type] += 1


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def notify_tool_start(
    session_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    model: str = "",
    provider: str = "",
) -> HookContext:
    """Convenience: fire on_tool_start and return context for on_tool_end."""
    ctx = HookContext(
        event="on_tool_start",
        session_id=session_id,
        tool_name=tool_name,
        tool_args=tool_args,
        model=model,
        provider=provider,
    )
    fire_hook("on_tool_start", ctx)
    return ctx


def notify_tool_end(
    ctx: HookContext,
    ok: bool = True,
    result_summary: str = "",
) -> None:
    """Convenience: fire on_tool_end with duration computed from start time."""
    ctx.tool_result_ok = ok
    ctx.tool_result_summary = result_summary
    ctx.tool_duration_ms = (time.time() - ctx.timestamp) * 1000
    fire_hook("on_tool_end", ctx)


def notify_model_call(
    session_id: str,
    model: str,
    provider: str,
    request_tokens: int = 0,
    response_tokens: int = 0,
    duration_ms: float = 0,
    finish_reason: str = "",
) -> None:
    """Convenience: fire on_model_call."""
    ctx = HookContext(
        event="on_model_call",
        session_id=session_id,
        model=model,
        provider=provider,
        model_request_tokens=request_tokens,
        model_response_tokens=response_tokens,
        model_duration_ms=duration_ms,
        model_finish_reason=finish_reason,
    )
    fire_hook("on_model_call", ctx)


def notify_error(
    session_id: str,
    error_type: str,
    error_message: str,
    error_traceback: str = "",
    model: str = "",
) -> None:
    """Convenience: fire on_error."""
    ctx = HookContext(
        event="on_error",
        session_id=session_id,
        model=model,
        error_type=error_type,
        error_message=error_message,
        error_traceback=error_traceback,
    )
    fire_hook("on_error", ctx)


def notify_compaction(
    session_id: str,
    tokens_before: int,
    tokens_after: int,
    reason: str = "",
) -> None:
    """Convenience: fire on_compaction."""
    ctx = HookContext(
        event="on_compaction",
        session_id=session_id,
        tokens_before=tokens_before,
        tokens_after=tokens_after,
        compaction_reason=reason,
    )
    fire_hook("on_compaction", ctx)


def notify_learning(
    session_id: str,
    learning_id: str,
    category: str = "",
) -> None:
    """Convenience: fire on_learn."""
    ctx = HookContext(
        event="on_learn",
        session_id=session_id,
        learning_id=learning_id,
        learning_category=category,
    )
    fire_hook("on_learn", ctx)


# ---------------------------------------------------------------------------
# Built-in hooks
# ---------------------------------------------------------------------------

def _builtin_tool_logger(ctx: HookContext) -> None:
    """Built-in hook: log every tool call summary to a metrics file."""
    try:
        fetih_home = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))
        log_path = Path(fetih_home) / "tool_metrics.jsonl"

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": ctx.tool_name,
            "ok": ctx.tool_result_ok,
            "duration_ms": round(ctx.tool_duration_ms, 1),
            "session": ctx.session_id[:8],
        }
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _builtin_slow_tool_alerter(ctx: HookContext) -> None:
    """Built-in hook: warn about slow tool calls (>10s)."""
    if ctx.tool_duration_ms > 10_000:
        logger.warning(
            "SLOW TOOL: %s took %.1fs — session=%s",
            ctx.tool_name,
            ctx.tool_duration_ms / 1000,
            ctx.session_id[:8],
        )


def _builtin_error_logger(ctx: HookContext) -> None:
    """Built-in hook: log errors to learnings error file."""
    if ctx.event == "on_error" and ctx.error_message:
        try:
            from fetih_cli.learnings import record_error
            record_error(
                error_message=ctx.error_message,
                context=f"session={ctx.session_id[:8]} model={ctx.model}",
                solution="",
                session_id=ctx.session_id,
            )
        except ImportError:
            pass


# Register built-in hooks at module load time
register_hook("on_tool_end", _builtin_tool_logger)
register_hook("on_tool_end", _builtin_slow_tool_alerter)
register_hook("on_error", _builtin_error_logger)


# ---------------------------------------------------------------------------
# Statistics API
# ---------------------------------------------------------------------------

def get_hook_stats() -> Dict[str, Any]:
    """Return collected hook statistics."""
    with _stats_lock:
        tool_avg = {}
        for name, times in _stats["tool_timing"].items():
            if times:
                tool_avg[name] = {
                    "count": len(times),
                    "avg_ms": round(sum(times) / len(times), 1),
                    "max_ms": round(max(times), 1),
                }

        model_avg = {}
        if _stats["model_timing"]:
            times = _stats["model_timing"]
            model_avg = {
                "count": len(times),
                "avg_ms": round(sum(times) / len(times), 1),
                "max_ms": round(max(times), 1),
            }

        return {
            "sessions": {
                "started": _stats["sessions_started"],
                "ended": _stats["sessions_ended"],
            },
            "tools": {
                "total_calls": _stats["total_tool_calls"],
                "failed": _stats["failed_tool_calls"],
                "timing": tool_avg,
                "busiest": sorted(
                    _stats["busy_tools"].items(),
                    key=lambda x: x[1], reverse=True,
                )[:10],
            },
            "model": {
                "total_calls": _stats["total_model_calls"],
                "timing": model_avg,
            },
            "compactions": _stats["total_compactions"],
            "errors": {
                "total": _stats["total_errors"],
                "by_type": dict(_stats["errors_by_type"]),
            },
        }


def get_active_hooks() -> Dict[str, int]:
    """Return count of registered hooks per event."""
    with _registry_lock:
        return {event: len(cbs) for event, cbs in _registry.items()}

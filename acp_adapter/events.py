"""Callback factories that turn FETIH agent signals into ACP updates.

The agent runtime reports progress through synchronous callbacks
(``tool_progress_callback``, ``step_callback``, ``stream_delta_callback``,
``reasoning_callback``) which fire on whatever thread runs the agent turn.
The ACP connection lives on the event loop, so every callback here builds the
ACP payload and hands it to :func:`_send_update`, which schedules the
``session_update`` coroutine on the loop in a leak-safe way.

Tool calls are tracked per tool *name* in FIFO order: the runtime does not
correlate "started" and "finished" signals for us, and the same tool can be
in flight twice at once (two ``terminal`` calls in one iteration).
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from typing import Any, Optional

from acp.schema import (
    AgentMessageChunk,
    AgentPlanUpdate,
    AgentThoughtChunk,
    PlanEntry,
    TextContentBlock,
)

from agent import display as agent_display

from acp_adapter.tools import (
    build_tool_complete,
    build_tool_start,
    make_tool_call_id,
)

logger = logging.getLogger(__name__)

# Agent tool-progress signals that announce a new tool call.
_START_SIGNAL_HINTS = ("start",)

# todo status -> ACP plan entry status.  ACP has no "cancelled" state, so a
# cancelled item is reported as completed with a marker in its content.
_PLAN_STATUS_MAP = {
    "completed": "completed",
    "in_progress": "in_progress",
    "pending": "pending",
    "cancelled": "completed",
}
_PLAN_PRIORITY = "medium"


def _send_update(conn, session_id: str, loop, update: Any) -> None:
    """Schedule ``conn.session_update`` for *update* on *loop*.

    Never raises: a closed loop during shutdown must not break the agent turn,
    and the coroutine is closed if scheduling fails so it is not reported as
    "never awaited".
    """
    if conn is None:
        return
    try:
        coro = conn.session_update(session_id=session_id, update=update)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("ACP session_update failed to build: %s", exc)
        return
    try:
        from agent.async_utils import safe_schedule_threadsafe

        safe_schedule_threadsafe(
            coro,
            loop,
            logger=logger,
            log_message="ACP session update could not be scheduled",
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("ACP session update scheduling failed: %s", exc)
        if asyncio.iscoroutine(coro):
            coro.close()


def _is_start_signal(signal: Any) -> bool:
    if signal is None:
        return True
    text = str(signal).lower()
    if "complete" in text or "finish" in text or "fail" in text:
        return False
    return any(hint in text for hint in _START_SIGNAL_HINTS)


def _coerce_args(args: Any) -> dict:
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _track_start(tool_call_ids: dict, tool_name: str, tc_id: str) -> None:
    holder = tool_call_ids.get(tool_name)
    if isinstance(holder, deque):
        holder.append(tc_id)
        return
    if holder is None:
        tool_call_ids[tool_name] = deque([tc_id])
        return
    # Tolerate a plain value (str) left by an older code path.
    tool_call_ids[tool_name] = deque([holder, tc_id])


def _pop_tool_call_id(tool_call_ids: dict, tool_name: str) -> Optional[str]:
    holder = tool_call_ids.get(tool_name)
    if holder is None:
        return None
    if isinstance(holder, deque):
        try:
            tc_id = holder.popleft()
        except IndexError:
            tool_call_ids.pop(tool_name, None)
            return None
        if not holder:
            tool_call_ids.pop(tool_name, None)
        return tc_id
    tool_call_ids.pop(tool_name, None)
    return holder


def make_tool_progress_cb(conn, session_id: str, loop, tool_call_ids: dict, tool_call_meta: dict):
    """Build the agent's ``tool_progress_callback``.

    Emits a ``ToolCallStart`` per started tool call and records the generated
    id (FIFO per tool name) plus the before-state snapshot used later by the
    completion renderer.
    """

    def cb(signal: Any, tool_name: Any, message: Any = None, args: Any = None) -> None:
        if not _is_start_signal(signal):
            return
        if not isinstance(tool_name, str) or not tool_name:
            return
        if not isinstance(tool_call_ids, dict):
            return

        parsed_args = _coerce_args(args)
        tc_id = make_tool_call_id()
        _track_start(tool_call_ids, tool_name, tc_id)

        if isinstance(tool_call_meta, dict):
            try:
                snapshot = agent_display.capture_local_edit_snapshot(tool_name, parsed_args)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("ACP snapshot capture failed for %s: %s", tool_name, exc)
                snapshot = None
            tool_call_meta[tc_id] = {"args": parsed_args, "snapshot": snapshot}

        update = build_tool_start(tc_id, tool_name, parsed_args)
        _send_update(conn, session_id, loop, update)

    return cb


def make_message_cb(conn, session_id: str, loop):
    """Build the agent's ``stream_delta_callback`` (assistant text chunks)."""

    def cb(text: Any) -> None:
        if not isinstance(text, str) or not text:
            return
        update = AgentMessageChunk(
            session_update="agent_message_chunk",
            content=TextContentBlock(type="text", text=text),
        )
        _send_update(conn, session_id, loop, update)

    return cb


def make_thinking_cb(conn, session_id: str, loop):
    """Build the agent's ``reasoning_callback`` (visible thinking chunks)."""

    def cb(text: Any) -> None:
        if not isinstance(text, str) or not text:
            return
        update = AgentThoughtChunk(
            session_update="agent_thought_chunk",
            content=TextContentBlock(type="text", text=text),
        )
        _send_update(conn, session_id, loop, update)

    return cb


def _loads_lenient(result: Any) -> Optional[dict]:
    if isinstance(result, dict):
        return result
    if not isinstance(result, str):
        return None
    text = result.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        marker = text.find("[Hint:")
        if marker == -1:
            return None
        try:
            data = json.loads(text[:marker].strip())
        except (TypeError, ValueError):
            return None
    return data if isinstance(data, dict) else None


def _build_plan_update_from_todo_result(result: Any) -> AgentPlanUpdate:
    """Translate a ``todo`` tool result into a native ACP plan update."""
    data = _loads_lenient(result)
    todos = data.get("todos") if isinstance(data, dict) else None
    entries: list[PlanEntry] = []
    if isinstance(todos, list):
        for item in todos:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "pending").strip().lower()
            content = str(item.get("content") or item.get("text") or "")
            if status == "cancelled":
                content = f"[cancelled] {content}"
            entries.append(
                PlanEntry(
                    content=content,
                    status=_PLAN_STATUS_MAP.get(status, "pending"),
                    priority=_PLAN_PRIORITY,
                )
            )
    return AgentPlanUpdate(session_update="plan", entries=entries)


def make_step_cb(conn, session_id: str, loop, tool_call_ids: dict, tool_call_meta: dict):
    """Build the agent's ``step_callback`` (per-iteration tool results).

    ``prev_tools`` entries are ``{"name", "result", "arguments"?}`` dicts or
    bare tool-name strings.
    """

    def cb(step_num: Any = None, prev_tools: Any = None) -> None:
        if not isinstance(prev_tools, (list, tuple)):
            return
        for info in prev_tools:
            if isinstance(info, str):
                tool_name, result, arguments = info, None, None
            elif isinstance(info, dict):
                tool_name = info.get("name")
                result = info.get("result")
                arguments = info.get("arguments")
            else:
                continue
            if not isinstance(tool_name, str) or not tool_name:
                continue
            if not isinstance(tool_call_ids, dict):
                continue

            tc_id = _pop_tool_call_id(tool_call_ids, tool_name)
            if tc_id is None:
                # Never started (or already completed) — nothing to update.
                continue

            meta = {}
            if isinstance(tool_call_meta, dict):
                raw_meta = tool_call_meta.pop(tc_id, None)
                if isinstance(raw_meta, dict):
                    meta = raw_meta

            function_args = arguments if isinstance(arguments, dict) else meta.get("args")
            update = build_tool_complete(
                tc_id,
                tool_name,
                result=result,
                function_args=function_args,
                snapshot=meta.get("snapshot"),
            )
            _send_update(conn, session_id, loop, update)

            if tool_name == "todo":
                plan = _build_plan_update_from_todo_result(result)
                _send_update(conn, session_id, loop, plan)

    return cb


__all__ = [
    "_build_plan_update_from_todo_result",
    "_send_update",
    "make_message_cb",
    "make_step_cb",
    "make_thinking_cb",
    "make_tool_progress_cb",
]

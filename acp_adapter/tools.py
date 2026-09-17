"""Tool-call rendering for the FETIH ACP adapter.

ACP clients (Zed, VS Code) render tool calls from structured ``ToolCallStart``
and ``ToolCallProgress`` payloads rather than from raw text.  This module owns
the translation from FETIH tool names + arguments + results into those
payloads: kind mapping, human-readable titles, and compact content blocks.

Design rules encoded here (all of them came from real Zed rendering bugs):

* Start events stay small.  File contents and diffs belong to the run, not to
  the "I am about to call this" card — the only exception is an auto-approved
  edit, where the approval prompt never appears so the diff is the only record
  the client will ever see.
* Completion events summarize.  A patch completion must never repeat the diff
  that was already shown in the approval card, and a memory write must never
  dump the raw entry list back into the transcript.
* Unknown tools still render.  Anything without a dedicated formatter falls
  back to a key/value rendering so plugin tools (memory_archive_search, ...)
  are readable instead of dumping a raw JSON blob.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Optional

from acp.schema import (
    ContentToolCallContent,
    FileEditToolCallContent,
    TextContentBlock,
    ToolCallLocation,
    ToolCallProgress,
    ToolCallStart,
)

# Tool name -> ACP ToolKind.  Zed picks its icon and affordance from this.
TOOL_KIND_MAP: dict[str, str] = {
    "read_file": "read",
    "search_files": "search",
    "terminal": "execute",
    "patch": "edit",
    "write_file": "edit",
    "process": "execute",
    "web_search": "fetch",
    "web_extract": "fetch",
    "execute_code": "execute",
    "todo": "other",
    "skill_view": "read",
    "skill_manage": "edit",
    "skills_list": "read",
    "vision_analyze": "read",
    "browser_navigate": "fetch",
    "browser_snapshot": "read",
    "browser_click": "execute",
    "browser_type": "execute",
    "browser_eval": "execute",
    "browser_back": "execute",
    "browser_press": "execute",
    "browser_scroll": "execute",
    "browser_get_images": "read",
    "browser_console_messages": "read",
    "memory": "other",
    "session_search": "search",
    "delegate_task": "other",
    "clarify": "other",
}

# Tools whose JSON ``{"error": ...}`` payload is a real failure.  Plugin tools
# (unknown names) legitimately return an ``error`` key as a data field, so the
# structured-error -> failed mapping only applies to tools we know.
_KNOWN_TOOL_NAMES = frozenset(TOOL_KIND_MAP)

# Long outputs are useless in a chat transcript and inflate every subsequent
# request, so display text is capped well below the model-visible limit.
MAX_DISPLAY_CHARS = 4000

_RAISED_TOOL_ERROR_RE = re.compile(r"^Error executing tool '[^']*':")
_HINT_RE = re.compile(r"\[Hint:\s*(.*?)\]", re.DOTALL)
_DRIVE_RE = re.compile(r"^([A-Za-z]):[/\\](.*)$")

_MAX_TITLE_COMMAND = 100


def get_tool_kind(tool_name: str) -> str:
    """Return the ACP ToolKind for *tool_name* (``other`` when unknown)."""
    if not isinstance(tool_name, str):
        return "other"
    return TOOL_KIND_MAP.get(tool_name, "other")


def make_tool_call_id() -> str:
    """Return a fresh, unique ACP tool call id."""
    return f"tc-{uuid.uuid4().hex[:12]}"


def _short(value: Any, limit: int = _MAX_TITLE_COMMAND) -> str:
    text = "" if value is None else str(value)
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 3)] + "..."


def _first_code_line(code: Any) -> str:
    if not isinstance(code, str):
        return ""
    for line in code.splitlines():
        if line.strip():
            return _short(line, 80)
    return ""


def _todo_items(args: dict) -> list:
    todos = args.get("todos") if isinstance(args, dict) else None
    if isinstance(todos, list):
        return [item for item in todos if isinstance(item, dict)]
    return []


def build_tool_title(tool_name: str, args: Optional[dict]) -> str:
    """Build the one-line title shown on a tool-call card."""
    args = args if isinstance(args, dict) else {}
    tool = tool_name if isinstance(tool_name, str) else str(tool_name)

    if tool == "terminal":
        return f"terminal: {_short(args.get('command'))}"
    if tool == "read_file":
        path = args.get("path") or ""
        return f"read: {_short(path, 80)}" if path else "read file"
    if tool == "write_file":
        path = args.get("path") or ""
        return f"write: {_short(path, 80)}" if path else "write file"
    if tool == "patch":
        path = args.get("path") or ""
        return f"patch: {_short(path, 80)}" if path else "patch file"
    if tool == "search_files":
        pattern = args.get("pattern")
        if pattern:
            return f"search: {_short(pattern, 80)}"
        return "search files"
    if tool == "process":
        action = args.get("action") or "list"
        session_id = args.get("session_id")
        if session_id:
            return f"process {action}: {_short(session_id, 40)}"
        return f"process {action}"
    if tool == "skill_view":
        name = args.get("name") or ""
        file_path = args.get("file_path")
        if file_path:
            return f"skill view ({name}/{file_path})"
        return f"skill view ({name})" if name else "skill view"
    if tool == "skill_manage":
        action = args.get("action") or "manage"
        name = args.get("name") or ""
        file_path = args.get("file_path")
        target = f"{name}/{file_path}" if file_path else str(name)
        return f"skill {action}: {target}".strip()
    if tool == "skills_list":
        return "list skills"
    if tool == "execute_code":
        first = _first_code_line(args.get("code") or args.get("command"))
        return f"python: {first}" if first else "python"
    if tool == "todo":
        count = len(_todo_items(args))
        return f"todo ({count} item)" if count == 1 else f"todo ({count} items)"
    if tool == "web_search":
        query = args.get("query")
        return f"web search: {_short(query, 80)}" if query else "web search"
    if tool == "web_extract":
        urls = args.get("urls")
        if isinstance(urls, list) and urls:
            return f"extract: {_short(urls[0], 80)}"
        url = args.get("url")
        return f"extract: {_short(url, 80)}" if url else "web extract"
    if tool == "browser_navigate":
        url = args.get("url")
        return f"navigate: {_short(url, 80)}" if url else "navigate"
    if tool == "browser_snapshot":
        return "browser snapshot"
    if tool == "vision_analyze":
        path = args.get("path") or args.get("image")
        return f"vision: {_short(path, 60)}" if path else "vision analyze"
    if tool == "memory":
        action = args.get("action") or "memory"
        target = args.get("target")
        if target:
            return f"memory {action} ({target})"
        return f"memory {action}"
    if tool == "session_search":
        query = args.get("query")
        return f"session search: {_short(query, 60)}" if query else "session search"
    if tool == "delegate_task":
        return "delegate task"
    return tool


def _text_block(text: str) -> ContentToolCallContent:
    return ContentToolCallContent(
        type="content",
        content=TextContentBlock(type="text", text=text),
    )


_LOCATION_TOOLS = frozenset({"read_file", "write_file", "patch"})


def extract_locations(args: Optional[dict]) -> list:
    """Return ACP file locations for a tool call (empty when there are none)."""
    if not isinstance(args, dict):
        return []
    path = args.get("path")
    if not isinstance(path, str) or not path:
        return []
    line = args.get("offset")
    if not isinstance(line, int) or isinstance(line, bool) or line < 0:
        line = None
    return [ToolCallLocation(path=path, line=line)]


def _todo_start_text(items: list) -> str:
    lines = []
    for index, item in enumerate(items, start=1):
        content = item.get("content") or item.get("text") or ""
        status = item.get("status") or "pending"
        lines.append(f"{index}. [{status}] {content}")
    return "\n".join(lines)


def _build_edit_content(path: str, old_text: Optional[str], new_text: Optional[str]):
    return FileEditToolCallContent(
        type="diff",
        path=path,
        old_text=old_text,
        new_text=new_text,
    )


def _approval_content(path: str) -> ContentToolCallContent:
    return _text_block(
        f"Approval prompt shows the diff for {path}"
    )


def build_tool_start(tc_id: str, tool_name: str, args: Optional[dict], edit_diff: Any = None) -> ToolCallStart:
    """Build the ``ToolCallStart`` payload for a tool that is about to run."""
    args = args if isinstance(args, dict) else {}
    tool = tool_name if isinstance(tool_name, str) else str(tool_name)
    kind = get_tool_kind(tool)
    path = args.get("path")
    path = path if isinstance(path, str) else ""

    content = None
    raw_input = None

    if tool == "skill_manage" and (args.get("action") or "") == "patch":
        name = args.get("name") or ""
        file_path = args.get("file_path") or ""
        content = [
            _build_edit_content(
                f"skills/{name}/{file_path}",
                args.get("old_string"),
                args.get("new_string"),
            )
        ]
    elif tool in {"write_file", "patch"}:
        new_text = getattr(edit_diff, "new_text", None) if edit_diff is not None else None
        if edit_diff is not None and path and new_text is not None:
            content = [
                _build_edit_content(
                    getattr(edit_diff, "path", path) or path,
                    getattr(edit_diff, "old_text", None),
                    new_text,
                )
            ]
        elif path:
            content = [_approval_content(path)]
            raw_input = args
        else:
            content = [_text_block(f"Approval prompt shows the diff for {tool}")]
            raw_input = args
    elif tool == "terminal":
        command = args.get("command") or ""
        content = [_text_block(f"```sh\n$ {command}\n```")]
        raw_input = args
    elif tool == "execute_code":
        code = args.get("code") or args.get("command") or ""
        content = [_text_block(f"```python\n{code}\n```")]
    elif tool == "read_file":
        content = None
    elif tool == "web_extract":
        content = None
    elif tool == "browser_navigate":
        content = [_text_block(json.dumps({"url": args.get("url")}, indent=2))]
    elif tool == "search_files":
        pattern = args.get("pattern") or ""
        target = args.get("target") or args.get("path") or "."
        content = [_text_block(f"Search: `{pattern}`\nTarget: {target}")]
    elif tool == "todo":
        items = _todo_items(args)
        content = [_text_block(_todo_start_text(items) or "No todos yet")]
    elif tool == "skill_view":
        name = args.get("name") or ""
        file_path = args.get("file_path")
        target = f"{name}/{file_path}" if file_path else str(name)
        content = [_text_block(f"Loading skill `{target}`")]
    elif tool == "process":
        action = args.get("action") or "list"
        command = args.get("command") or ""
        session_id = args.get("session_id") or ""
        detail = _short(command or session_id, 80)
        content = [_text_block(f"Process {action} {detail}".strip())]
    elif tool == "web_search":
        content = [_text_block(f"Searching the web for `{args.get('query') or ''}`")]
    elif tool == "memory":
        content = [_text_block(f"Memory {args.get('action') or 'operation'}")]
    elif tool == "session_search":
        content = [_text_block(f"Searching sessions for `{args.get('query') or ''}`")]
    elif tool == "delegate_task":
        content = [_text_block("Delegating task to subagents")]
    else:
        body = json.dumps(args, indent=2, ensure_ascii=False, default=str) if args else ""
        content = [_text_block(body)]
        raw_input = args

    return ToolCallStart(
        session_update="tool_call",
        tool_call_id=tc_id,
        title=build_tool_title(tool, args),
        kind=kind,
        status="in_progress",
        content=content,
        raw_input=raw_input,
        locations=extract_locations(args),
    )


# ---------------------------------------------------------------------------
# Completion rendering
# ---------------------------------------------------------------------------


def _split_hint(text: str) -> tuple[str, Optional[str]]:
    """Split a trailing ``[Hint: ...]`` marker off a tool result."""
    match = _HINT_RE.search(text)
    if match is None:
        return text, None
    body = text[: match.start()].strip()
    return body, match.group(0).strip()


def _parse_json_result(result: Any) -> tuple[Optional[Any], Optional[str]]:
    """Parse a JSON tool result, tolerating a trailing ``[Hint: ...]`` block."""
    if isinstance(result, (dict, list)):
        return result, None
    if not isinstance(result, str):
        return None, None
    body, hint = _split_hint(result.strip())
    if not body:
        return None, hint
    try:
        return json.loads(body), hint
    except (TypeError, ValueError):
        return None, hint


def _is_failure(tool: str, data: Any, text: str) -> bool:
    if isinstance(data, dict):
        if data.get("success") is False:
            return True
        if data.get("ok") is False:
            return True
        exit_code = data.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
            return True
        returncode = data.get("returncode")
        if isinstance(returncode, int) and not isinstance(returncode, bool) and returncode != 0:
            return True
        if "error" in data and data.get("error") and tool in _KNOWN_TOOL_NAMES:
            return True
        return False
    if isinstance(text, str) and _RAISED_TOOL_ERROR_RE.match(text.strip()):
        return True
    return False


def _terminal_text(data: Any, text: str, args: Optional[dict]) -> str:
    command = ""
    if isinstance(args, dict) and isinstance(args.get("command"), str):
        command = args["command"]
    if isinstance(data, dict):
        output = data.get("output")
        if output is None:
            output = data.get("stdout")
        parts = []
        if command:
            parts.append(f"$ {command}")
        if output is not None:
            parts.append(str(output))
        stderr = data.get("stderr")
        if stderr:
            parts.append(str(stderr))
        if not parts:
            return text
        return "\n".join(parts)
    if command:
        return f"$ {command}\n\n{text}"
    return text


def _todo_text(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    todos = data.get("todos")
    if not isinstance(todos, list):
        return ""
    icons = {
        "completed": "✅",
        "in_progress": "- 🔄",
        "pending": "- ⏳",
        "cancelled": "- ❌",
    }
    counts = {"completed": 0, "in_progress": 0, "pending": 0, "cancelled": 0}
    lines = []
    for item in todos:
        if not isinstance(item, dict):
            continue
        status = item.get("status") or "pending"
        counts[status] = counts.get(status, 0) + 1
        prefix = icons.get(status, "- ⏳")
        lines.append(f"{prefix} {item.get('content') or item.get('text') or ''}".rstrip())
    lines.append(
        f"**Progress:** {counts.get('completed', 0)} completed, "
        f"{counts.get('in_progress', 0)} in progress, "
        f"{counts.get('pending', 0)} pending"
    )
    return "\n".join(lines)


def _skill_view_text(data: Any, text: str) -> str:
    if not isinstance(data, dict):
        return text
    name = data.get("name") or ""
    description = data.get("description") or ""
    content = data.get("content") or ""
    lines = [f"**Skill loaded** `{name}`" + (f" — {description}" if description else "")]
    if isinstance(content, str) and content.strip():
        first_line = next((ln for ln in content.splitlines() if ln.strip()), "")
        if first_line:
            lines.append(first_line.strip())
    lines.append("Full skill content is available to the agent")
    return "\n".join(lines)


def _skill_manage_text(data: Any, text: str, args: Optional[dict]) -> str:
    action = ""
    name = ""
    file_path = ""
    if isinstance(args, dict):
        action = args.get("action") or ""
        name = args.get("name") or ""
        file_path = args.get("file_path") or ""
    if not isinstance(data, dict):
        return text
    if data.get("success") is False:
        return f"**❌ Skill {action or 'update'} failed**\n{data.get('error') or text}"
    lines = [f"**✅ Skill updated** `{action or 'update'}`"]
    if name:
        lines.append(f"Skill: `{name}`")
    if file_path:
        lines.append(f"File: {file_path}")
    message = data.get("message")
    if message:
        lines.append(str(message))
    return "\n".join(lines)


def _read_file_text(data: Any, text: str, args: Optional[dict]) -> str:
    path = args.get("path") if isinstance(args, dict) else None
    header = f"Read {path}" if path else "Read file"
    if not isinstance(data, dict):
        return f"{header}\n\n{text}"
    body = data.get("content")
    if isinstance(body, str):
        return f"{header}\n\n```\n{body}\n```"
    return f"{header}\n\n{text}"


def _search_text(data: Any, text: str, hint: Optional[str]) -> str:
    lines: list[str] = []
    if isinstance(data, dict) and isinstance(data.get("matches"), list):
        matches = data["matches"]
        total = data.get("total_count", len(matches))
        lines.append("Search results")
        lines.append(f"Found {total} matches")
        for match in matches:
            if not isinstance(match, dict):
                continue
            path = match.get("path") or ""
            line_no = match.get("line")
            where = f"{path}:{line_no}" if line_no is not None else str(path)
            content = match.get("content") or ""
            lines.append(f"- {where}: {content}".rstrip())
        if data.get("truncated") and not hint:
            lines.append("Results are truncated — use offset to page through the rest.")
    elif isinstance(data, dict) and isinstance(data.get("files"), list):
        files = data["files"]
        total = data.get("total_count", len(files))
        lines.append("File search results")
        lines.append(f"Found {total} files; showing {len(files)}.")
        for path in files:
            lines.append(f"- {path}")
        if data.get("truncated"):
            lines.append("Results are truncated — use offset to page through the rest.")
    else:
        return text
    if hint:
        lines.append(hint)
    return "\n".join(lines)


def _process_text(data: Any, text: str) -> str:
    if not isinstance(data, dict) or not isinstance(data.get("processes"), list):
        return text
    processes = data["processes"]
    lines = [f"Processes: {len(processes)}"]
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        session_id = proc.get("session_id") or proc.get("id") or "?"
        status = proc.get("status") or "unknown"
        pid = proc.get("pid")
        command = proc.get("command") or ""
        detail = f"- `{session_id}` [{status}]"
        if pid is not None:
            detail += f" pid={pid}"
        if command:
            detail += f" — {command}"
        lines.append(detail)
    return "\n".join(lines)


def _delegate_text(data: Any, text: str) -> str:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return text
    results = data["results"]
    lines = [f"Delegation results: {len(results)} task" + ("" if len(results) == 1 else "s")]
    for item in results:
        if not isinstance(item, dict):
            continue
        index = item.get("task_index", 0)
        status = item.get("status") or "unknown"
        lines.append(f"- Task {index}: {status}")
        summary = item.get("summary")
        if summary:
            lines.append(f"  {summary}")
        model = item.get("model")
        if model:
            lines.append(f"  Model: {model}")
        duration = item.get("duration_seconds")
        if duration is not None:
            lines.append(f"  Duration: {duration}s")
        trace = item.get("tool_trace")
        if isinstance(trace, list) and trace:
            tools = [t.get("tool") for t in trace if isinstance(t, dict) and t.get("tool")]
            if tools:
                lines.append(f"  Tools: {', '.join(tools)}")
    return "\n".join(lines)


def _session_search_text(data: Any, text: str) -> str:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return text
    lines = ["Recent sessions"]
    for item in data["results"]:
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("session_id") or ""
        lines.append(f"- {title}")
        preview = item.get("preview")
        if preview:
            lines.append(f"  {preview}")
    return "\n".join(lines)


def _memory_text(data: Any, text: str, args: Optional[dict]) -> str:
    if not isinstance(data, dict):
        return text
    action = args.get("action") if isinstance(args, dict) else None
    if action == "add":
        content = args.get("content") if isinstance(args, dict) else ""
        lines = ["Memory add saved"]
        if content:
            lines.append(str(content))
        return "\n".join(lines)
    if data.get("success") is False:
        return f"Memory operation failed\n{data.get('error') or text}"
    lines = [f"Memory {action or 'operation'}"]
    message = data.get("message")
    if message:
        lines.append(str(message))
    usage = data.get("usage")
    if usage:
        lines.append(f"Usage: {usage}")
    return "\n".join(lines)


def _web_extract_text(data: Any, text: str) -> tuple[Optional[str], bool]:
    """Return (display_text, has_error) for web_extract results."""
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return text, _is_failure("web_extract", data, text)
    errors = []
    for item in data["results"]:
        if isinstance(item, dict) and item.get("error"):
            errors.append(item)
    if not errors:
        return None, False
    lines = ["Web extract failed"]
    for item in errors:
        url = item.get("url") or ""
        lines.append(f"- {url}: {item.get('error')}")
    return "\n".join(lines), True


def _patch_text(data: Any, text: str, args: Optional[dict]) -> str:
    lines = ["✅ patch completed"]
    if isinstance(data, dict):
        files = data.get("files_modified")
        if isinstance(files, list) and files:
            lines.append("Modified: " + ", ".join(str(f) for f in files))
        message = data.get("message")
        if message:
            lines.append(str(message))
    if len(lines) == 1 and isinstance(args, dict) and args.get("path"):
        lines.append(f"File: {args['path']}")
    return "\n".join(lines)


def _write_file_text(data: Any, text: str, args: Optional[dict]) -> str:
    lines = ["✅ write_file completed"]
    if isinstance(data, dict):
        written = data.get("bytes_written")
        if written is not None:
            lines.append(f"Wrote {written} bytes")
    if isinstance(args, dict) and args.get("path"):
        lines.append(f"File: {args['path']}")
    return "\n".join(lines)


def _format_scalar(value: Any) -> str:
    return str(value)


def _format_lines(key: str, value: Any, indent: str = "") -> list:
    """Render one JSON key as human-readable markdown-ish lines.

    Nested containers get a ``**key:**`` header followed by indented children
    so a plugin tool result never dumps a raw JSON blob into the transcript.
    """
    if isinstance(value, dict):
        if not value:
            return [f"{indent}**{key}:** (empty)"]
        lines = [f"{indent}**{key}:**"]
        for sub_key, sub_value in value.items():
            lines.extend(_format_lines(str(sub_key), sub_value, indent + "  "))
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{indent}**{key}:** (empty)"]
        lines = [f"{indent}**{key}:** {len(value)} items"]
        for item in value[:5]:
            if isinstance(item, dict):
                for sub_key, sub_value in list(item.items())[:6]:
                    lines.extend(_format_lines(str(sub_key), sub_value, indent + "  - "))
            else:
                lines.append(f"{indent}- {_format_scalar(item)}")
        return lines
    return [f"{indent}**{key}:** {_format_scalar(value)}"]


def _generic_text(tool: str, data: Any, text: str) -> str:
    if isinstance(data, dict):
        lines = [f"**{tool} result**"]
        for key, value in data.items():
            lines.extend(_format_lines(str(key), value))
        return "\n".join(lines)
    if isinstance(data, list):
        lines = [f"{tool}: {len(data)} items"]
        for item in data[:5]:
            if isinstance(item, dict):
                for sub_key, sub_value in list(item.items())[:4]:
                    lines.append(f"- **{sub_key}:** {_format_scalar(sub_value)}")
            else:
                lines.append(f"- {_format_scalar(item)}")
        return "\n".join(lines)
    return text


def _truncate(text: str) -> str:
    if len(text) <= MAX_DISPLAY_CHARS:
        return text
    return text[:MAX_DISPLAY_CHARS] + "\n\n... (output truncated) ..."


def build_tool_complete(
    tc_id: str,
    tool_name: str,
    result: Any = None,
    *,
    function_args: Optional[dict] = None,
    snapshot: Any = None,
) -> ToolCallProgress:
    """Build the ``ToolCallProgress`` payload for a finished tool call."""
    tool = tool_name if isinstance(tool_name, str) else str(tool_name)
    args = function_args if isinstance(function_args, dict) else None

    raw_text = "" if result is None else (result if isinstance(result, str) else json.dumps(result, default=str))
    data, hint = _parse_json_result(result)

    failed = _is_failure(tool, data, raw_text)
    text: Optional[str]
    content: Optional[list] = None

    if tool == "todo":
        text = _todo_text(data) or raw_text or "No todos"
    elif tool == "skill_view":
        text = _skill_view_text(data, raw_text)
    elif tool == "skill_manage":
        text = _skill_manage_text(data, raw_text, args)
    elif tool == "read_file":
        text = _read_file_text(data, raw_text, args)
    elif tool == "search_files":
        text = _search_text(data, raw_text, hint)
    elif tool == "process":
        text = _process_text(data, raw_text)
    elif tool == "delegate_task":
        text = _delegate_text(data, raw_text)
    elif tool == "session_search":
        text = _session_search_text(data, raw_text)
    elif tool == "memory":
        text = _memory_text(data, raw_text, args)
    elif tool == "web_extract":
        text, extract_failed = _web_extract_text(data, raw_text)
        failed = failed or extract_failed
    elif tool == "terminal":
        text = _terminal_text(data, raw_text, args)
    elif tool == "execute_code":
        if isinstance(data, dict) and data.get("output") is not None:
            exit_code = data.get("exit_code")
            parts = []
            if exit_code is not None:
                parts.append(f"Exit code: {exit_code}")
            parts.append(str(data.get("output")))
            text = "\n\n".join(parts)
        else:
            text = raw_text
    elif tool == "patch":
        text = _patch_text(data, raw_text, args)
    elif tool == "write_file":
        text = _write_file_text(data, raw_text, args)
    else:
        text = _generic_text(tool, data, raw_text)

    if text is not None:
        content = [_text_block(_truncate(text))]

    return ToolCallProgress(
        session_update="tool_call_update",
        tool_call_id=tc_id,
        title=build_tool_title(tool, args),
        kind=get_tool_kind(tool),
        status="failed" if failed else "completed",
        content=content,
        raw_output=None,
    )

"""Pre-edit approval bridge between ACP sessions and the tool runtime.

``model_tools.handle_function_call`` calls :func:`maybe_require_edit_approval`
before running ``write_file`` / ``patch``.  When an ACP session has registered
a requester (see :func:`set_edit_approval_requester`) the edit is held until
the ACP client approves it, and a denial is returned as a structured tool
error instead of touching the filesystem.

The requester lives in a :class:`contextvars.ContextVar` so that concurrent
sessions — and the ``contextvars.copy_context()`` thread handoff the ACP
session runner uses — each see their own callback.  When no requester is
registered (CLI, gateway, cron) the guard is a no-op.
"""

from __future__ import annotations

import contextvars
import json
import logging
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from acp.schema import (
    ContentToolCallContent,
    FileEditToolCallContent,
    TextContentBlock,
    ToolCallProgress,
)

logger = logging.getLogger(__name__)

# Tools that mutate files and therefore need approval.
_GATED_TOOLS = frozenset({"write_file", "patch"})

_DENIED_PREFIX = "Edit approval denied"

# Never auto-approve these, even inside the workspace: a compromised agent
# should not be able to silently rewrite credentials.
_SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "secrets.yaml",
        "secrets.yml",
        "shadow",
    }
)
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore")

_TEMP_ROOTS = ("/tmp", "/var/tmp", "/private/tmp")

# Modes that allow edits inside the session workspace without asking.
_WORKSPACE_SCOPED_MODES = frozenset({"workspace_session", "accept_edits"})
# Modes that allow any edit without asking (still never sensitive files).
_UNRESTRICTED_MODES = frozenset({"dont_ask", "allow_all"})


@dataclass
class EditProposal:
    """A pending file edit awaiting approval."""

    tool_name: str
    path: str
    old_text: Optional[str]
    new_text: Optional[str]
    arguments: dict = field(default_factory=dict)


_requester: contextvars.ContextVar[Optional[Callable[[EditProposal], bool]]] = (
    contextvars.ContextVar("fetih_acp_edit_approval_requester", default=None)
)
# Mutable holder so the guards test can key off thread identity without
# leaking the callback into unrelated threads.
_requester_thread: threading.local = threading.local()


def set_edit_approval_requester(requester: Callable[[EditProposal], bool]) -> None:
    """Register *requester* for edits made in the current context."""
    _requester.set(requester)
    _requester_thread.owner = threading.get_ident()


def clear_edit_approval_requester() -> None:
    """Unregister the current context's edit requester."""
    _requester.set(None)
    _requester_thread.owner = None


def get_edit_approval_requester() -> Optional[Callable[[EditProposal], bool]]:
    """Return the requester for the current context, if any."""
    return _requester.get()


def _read_text(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def build_edit_proposal(tool_name: str, arguments: dict) -> Optional[EditProposal]:
    """Build the diff proposal for a gated tool call.

    ``write_file`` reports the previous file body (``None`` for a new file).
    ``patch`` in ``replace`` mode reports the *full file* before/after bodies,
    which is what Zed's approval card renders as a diff.
    """
    if not isinstance(arguments, dict):
        return None
    path = arguments.get("path")
    if not isinstance(path, str) or not path:
        return None

    if tool_name == "write_file":
        new_text = arguments.get("content")
        new_text = new_text if isinstance(new_text, str) else ""
        return EditProposal(tool_name, path, _read_text(path), new_text, arguments)

    if tool_name == "patch":
        mode = arguments.get("mode") or "replace"
        if mode != "replace":
            # Blob/apply modes do not describe a single old->new string pair;
            # the client sees the raw patch in the approval card instead.
            return EditProposal(tool_name, path, _read_text(path), None, arguments)
        old_string = arguments.get("old_string")
        new_string = arguments.get("new_string")
        if not isinstance(old_string, str) or not isinstance(new_string, str):
            return EditProposal(tool_name, path, _read_text(path), None, arguments)
        before = _read_text(path)
        if before is None:
            return EditProposal(tool_name, path, None, None, arguments)
        if old_string not in before:
            return EditProposal(tool_name, path, before, before, arguments)
        replace_all = bool(arguments.get("replace_all"))
        after = before.replace(old_string, new_string) if replace_all else before.replace(old_string, new_string, 1)
        return EditProposal(tool_name, path, before, after, arguments)

    return None


def build_acp_edit_tool_call(proposal: EditProposal) -> ToolCallProgress:
    """Build the ACP tool-call payload shown on the approval card."""
    if proposal.new_text is None:
        # Blob/apply patches have no single old->new pair to diff; the client
        # still needs a body to render.
        content = [
            ContentToolCallContent(
                type="content",
                content=TextContentBlock(
                    type="text",
                    text=f"Approve {proposal.tool_name} on {proposal.path}",
                ),
            )
        ]
    else:
        content = [
            FileEditToolCallContent(
                type="diff",
                path=proposal.path,
                old_text=proposal.old_text,
                new_text=proposal.new_text,
            )
        ]
    return ToolCallProgress(
        session_update="tool_call_update",
        tool_call_id=f"edit-{uuid.uuid4().hex[:12]}",
        title=f"Approve {proposal.tool_name}: {proposal.path}",
        kind="edit",
        status="pending",
        content=content,
        raw_input={"tool": proposal.tool_name, "arguments": proposal.arguments},
    )


def maybe_require_edit_approval(function_name: str, function_args: Any) -> Optional[str]:
    """Block a gated edit until the ACP client approves it.

    Returns ``None`` when the edit may proceed, or a JSON tool-error string
    (the same shape the tool runtime uses for failures) when it must not.
    """
    if function_name not in _GATED_TOOLS:
        return None
    requester = _requester.get()
    if requester is None:
        return None

    proposal = build_edit_proposal(function_name, function_args if isinstance(function_args, dict) else {})
    if proposal is None:
        return None

    try:
        approved = bool(requester(proposal))
    except Exception as exc:  # client disconnected, cancelled, ...
        logger.warning("ACP edit approval requester failed: %s", exc)
        return json.dumps(
            {"error": f"{_DENIED_PREFIX}: approval request failed ({exc})"},
            ensure_ascii=False,
        )

    if approved:
        return None

    logger.info("ACP edit approval denied for %s", proposal.path)
    return json.dumps(
        {"error": f"{_DENIED_PREFIX}: {function_name} on {proposal.path} was not approved by the client"},
        ensure_ascii=False,
    )


def _is_sensitive_path(path: str) -> bool:
    try:
        parts = Path(path).parts
    except (TypeError, ValueError):
        return True
    for part in parts:
        lowered = part.lower()
        if lowered in _SENSITIVE_NAMES:
            return True
        if any(lowered.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
            return True
    return False


def _normalized(path: str) -> str:
    return str(path).replace("\\", "/").rstrip("/").lower()


def _is_temp_path(path: str) -> bool:
    candidate = _normalized(path)
    for root in _TEMP_ROOTS:
        if candidate == root or candidate.startswith(root + "/"):
            return True
    try:
        temp_root = _normalized(tempfile.gettempdir())
    except Exception:  # pragma: no cover - tempfile is always available
        return False
    if not temp_root:
        return False
    return candidate == temp_root or candidate.startswith(temp_root + "/")


def _is_inside(path: str, root: str) -> bool:
    candidate = _normalized(path)
    base = _normalized(root)
    if not base:
        return False
    return candidate == base or candidate.startswith(base + "/")


def should_auto_approve_edit(proposal: EditProposal, mode: Optional[str], cwd: Optional[str] = None) -> bool:
    """Decide whether *proposal* can skip the approval prompt.

    Sensitive files are never auto-approved.  Otherwise ``workspace_session``
    (the ACP "accept edits" mode) auto-approves edits inside the session cwd
    and inside the system temp directory; the unconditionally-permissive
    modes auto-approve everything else.
    """
    path = getattr(proposal, "path", None)
    if not isinstance(path, str) or not path:
        return False
    if _is_sensitive_path(path):
        return False

    normalized_mode = (mode or "").strip().lower()
    if normalized_mode in _UNRESTRICTED_MODES:
        return True
    if normalized_mode in _WORKSPACE_SCOPED_MODES:
        if _is_temp_path(path):
            return True
        if cwd and _is_inside(path, cwd):
            return True
        return False
    return False


__all__ = [
    "EditProposal",
    "build_acp_edit_tool_call",
    "build_edit_proposal",
    "clear_edit_approval_requester",
    "get_edit_approval_requester",
    "maybe_require_edit_approval",
    "set_edit_approval_requester",
    "should_auto_approve_edit",
]

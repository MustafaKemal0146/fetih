"""Dangerous-command and edit approvals driven by the ACP client.

The tool runtime asks for approval synchronously from whatever thread runs the
agent turn (``threading.local`` callback set by ``tools.terminal_tool``).  ACP
approval is asynchronous: it is a ``session/request_permission`` round trip to
the client.  The bridge here is the seam between those two worlds —

1. build the ACP tool call + permission options,
2. call ``request_permission`` eagerly so the coroutine exists,
3. schedule it on the ACP event loop from this thread,
4. block on the returned future with a timeout, and
5. map the client's answer back onto the runtime's vocabulary
   (``once`` / ``session`` / ``always`` / ``deny``).

A denied, timed-out, cancelled, failed or unschedulable request always denies.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Optional

from acp.schema import (
    ContentToolCallContent,
    PermissionOption,
    TextContentBlock,
    ToolCallProgress,
)

from acp_adapter.edit_approval import EditProposal, build_acp_edit_tool_call

logger = logging.getLogger(__name__)

ALLOW_ONCE = "allow_once"
ALLOW_SESSION = "allow_session"
ALLOW_ALWAYS = "allow_always"
DENY = "deny"
DENY_ALWAYS = "deny_always"

# ACP option id -> the vocabulary ``prompt_dangerous_approval`` understands.
_OUTCOME_MAP = {
    ALLOW_ONCE: "once",
    ALLOW_SESSION: "session",
    ALLOW_ALWAYS: "always",
}

DEFAULT_APPROVAL_TIMEOUT = 300.0

_PERMISSION_ID_PREFIX = "perm-check-"


def _build_permission_tool_call(command: str, description: str) -> ToolCallProgress:
    """Build the approval card payload for a dangerous command."""
    return ToolCallProgress(
        session_update="tool_call_update",
        tool_call_id=f"{_PERMISSION_ID_PREFIX}{uuid.uuid4().hex[:12]}",
        title=f"Approve dangerous command: {command} — {description}",
        kind="execute",
        status="pending",
        content=[
            ContentToolCallContent(
                type="content",
                content=TextContentBlock(
                    type="text",
                    text=f"$ {command}\n\n{description}",
                ),
            )
        ],
        raw_input={"command": command, "description": description},
    )


def _build_permission_options(allow_permanent: bool = True) -> list:
    """Build the approval options offered to the client."""
    options = [
        PermissionOption(option_id=ALLOW_ONCE, name="Allow once", kind="allow_once"),
        PermissionOption(option_id=ALLOW_SESSION, name="Allow for this session", kind="allow_always"),
    ]
    if allow_permanent:
        options.append(
            PermissionOption(option_id=ALLOW_ALWAYS, name="Always allow", kind="allow_always")
        )
    options.append(PermissionOption(option_id=DENY, name="Deny", kind="reject_once"))
    options.append(PermissionOption(option_id=DENY_ALWAYS, name="Always deny", kind="reject_always"))
    return options


def _await_permission(
    request_permission: Callable,
    loop,
    timeout: float,
    **kwargs: Any,
) -> Optional[str]:
    """Ask the client for permission and return its raw option id (or None)."""
    try:
        coro = request_permission(**kwargs)
    except Exception as exc:
        logger.warning("ACP permission request could not be built: %s", exc)
        return None

    from agent.async_utils import safe_schedule_threadsafe

    future = safe_schedule_threadsafe(
        coro,
        loop,
        logger=logger,
        log_message="ACP permission request could not be scheduled",
    )
    if future is None:
        return None

    try:
        response = future.result(timeout=timeout)
    except TimeoutError as exc:
        logger.warning("ACP permission request timed out: %s", exc)
        try:
            future.cancel()
        except Exception:  # pragma: no cover - defensive
            pass
        return None
    except Exception as exc:
        logger.warning("ACP permission request failed: %s", exc)
        return None

    if response is None:
        return None
    outcome = getattr(response, "outcome", None)
    if outcome is None:
        return None
    option_id = getattr(outcome, "option_id", None)
    if isinstance(option_id, str) and option_id:
        return option_id
    return None


def _map_option_id(option_id: Optional[str]) -> str:
    if option_id is None:
        return "deny"
    return _OUTCOME_MAP.get(option_id, "deny")


def make_approval_callback(
    request_permission: Callable,
    loop,
    session_id: str = "",
    timeout: float = DEFAULT_APPROVAL_TIMEOUT,
) -> Callable[..., str]:
    """Build the ``approval_callback`` handed to the terminal tool."""

    def cb(command: str, description: str, allow_permanent: bool = True) -> str:
        tool_call = _build_permission_tool_call(command, description)
        options = _build_permission_options(allow_permanent)
        option_id = _await_permission(
            request_permission,
            loop,
            timeout,
            session_id=session_id,
            tool_call=tool_call,
            options=options,
        )
        decision = _map_option_id(option_id)
        logger.debug("ACP approval decision for %r: %s", command, decision)
        return decision

    return cb


def _edit_options() -> list:
    return [
        PermissionOption(option_id=ALLOW_ONCE, name="Apply edit", kind="allow_once"),
        PermissionOption(option_id=DENY, name="Reject edit", kind="reject_once"),
    ]


def make_edit_approval_requester(
    request_permission: Callable,
    loop,
    session_id: str = "",
    timeout: float = DEFAULT_APPROVAL_TIMEOUT,
) -> Callable[[EditProposal], bool]:
    """Build the requester used by the pre-edit approval gate."""

    def requester(proposal: EditProposal) -> bool:
        tool_call = build_acp_edit_tool_call(proposal)
        option_id = _await_permission(
            request_permission,
            loop,
            timeout,
            session_id=session_id,
            tool_call=tool_call,
            options=_edit_options(),
        )
        return option_id == ALLOW_ONCE

    return requester


__all__ = [
    "ALLOW_ALWAYS",
    "ALLOW_ONCE",
    "ALLOW_SESSION",
    "DENY",
    "DENY_ALWAYS",
    "DEFAULT_APPROVAL_TIMEOUT",
    "make_approval_callback",
    "make_edit_approval_requester",
]

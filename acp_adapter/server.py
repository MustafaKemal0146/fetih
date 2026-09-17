"""The ACP agent implementation.

``FETIHACPAgent`` is the object ACP clients talk to: it maps the protocol's
session lifecycle onto :class:`~acp_adapter.session.SessionManager` and streams
an agent turn's progress back as ``session/update`` notifications.

The whole turn runs on a worker thread (``run_in_executor``) because the agent
runtime is synchronous; only the notification plumbing touches the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Optional

import acp
from acp.schema import (
    AgentCapabilities,
    AgentMessageChunk,
    AgentPlanUpdate,
    AuthenticateResponse,
    AvailableCommand,
    AvailableCommandInput,
    CloseSessionResponse,
    ForkSessionResponse,
    Implementation,
    InitializeResponse,
    ListSessionsResponse,
    LoadSessionResponse,
    McpServerHttp,
    McpServerStdio,
    ModelInfo,
    NewSessionResponse,
    PromptResponse,
    ResumeSessionResponse,
    SessionCapabilities,
    SessionInfo,
    SessionInfoUpdate,
    SessionMode,
    SessionModeState,
    SessionModelState,
    SetSessionConfigOptionResponse,
    SetSessionModelResponse,
    SetSessionModeResponse,
    TextContentBlock,
    UnstructuredCommandInput,
    Usage,
    UsageUpdate,
    UserMessageChunk,
)

from acp_adapter import FETIH_VERSION, events
from acp_adapter.auth import (
    TERMINAL_SETUP_AUTH_METHOD_ID,
    build_auth_methods,
    detect_provider,
)
from acp_adapter.session import SessionManager, SessionState
from acp_adapter.tools import build_tool_complete, build_tool_start

logger = logging.getLogger(__name__)

AGENT_NAME = "fetih-agent"

# Sessions returned per ``session/list`` page.
_LIST_SESSIONS_PAGE_SIZE = 20

# The ACP session modes double as the edit-approval policy selector: an editor
# shows them in its mode dropdown.
_MODE_DEFINITIONS = (
    ("default", "Default"),
    ("accept_edits", "Accept Edits"),
    ("dont_ask", "Don't Ask"),
)
_DEFAULT_MODE = "default"

# Edit-approval policy value -> session mode id.
_POLICY_TO_MODE = {
    "ask": "default",
    "default": "default",
    "accept_edits": "accept_edits",
    "workspace_session": "accept_edits",
    "dont_ask": "dont_ask",
    "allow_all": "dont_ask",
}
# Session mode id -> edit-approval policy value.
_MODE_TO_POLICY = {
    "default": "ask",
    "accept_edits": "workspace_session",
    "dont_ask": "dont_ask",
}

# Command name -> (description, input hint).  The hint is None for commands
# that take no argument.
_COMMAND_SPECS = (
    ("help", "List available commands", None),
    ("model", "Show or switch the active model", "model name to switch to"),
    ("tools", "List the tools available to the agent", None),
    ("context", "Show context window usage", None),
    ("reset", "Clear the conversation history", None),
    ("compact", "Compress the conversation to free context", None),
    ("steer", "Queue guidance for the next turn", "guidance text"),
    ("queue", "Queue a message for the next turn", "message text"),
    ("version", "Show the FETIH version", None),
)
_ADVERTISED_COMMANDS = tuple(name for name, _desc, _hint in _COMMAND_SPECS)

_DEFAULT_TOOLSET = "fetih-acp"


def _mode_state(current: Optional[str]) -> SessionModeState:
    mode_id = current if current in {m for m, _ in _MODE_DEFINITIONS} else _DEFAULT_MODE
    return SessionModeState(
        available_modes=[SessionMode(id=mid, name=name) for mid, name in _MODE_DEFINITIONS],
        current_mode_id=mode_id,
    )


def _text_of(block: Any) -> str:
    if isinstance(block, str):
        return block
    text = getattr(block, "text", None)
    if isinstance(text, str):
        return text
    if getattr(block, "type", None) == "resource_link":
        uri = getattr(block, "uri", None)
        if isinstance(uri, str):
            return uri
    resource = getattr(block, "resource", None)
    inner = getattr(resource, "text", None)
    if isinstance(inner, str):
        return inner
    return ""


def _prompt_text(prompt: Any) -> str:
    if isinstance(prompt, str):
        return prompt
    if not isinstance(prompt, (list, tuple)):
        return ""
    parts = [text for text in (_text_of(block) for block in prompt) if text]
    return "\n".join(parts)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _reasoning_text(message: dict) -> str:
    for key in ("reasoning_content", "reasoning"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _parse_arguments(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _tool_calls_of(message: dict) -> list:
    calls = message.get("tool_calls")
    if not isinstance(calls, list):
        return []
    result = []
    for call in calls:
        if not isinstance(call, dict):
            continue
        function = call.get("function")
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name:
            continue
        call_id = call.get("id")
        if not isinstance(call_id, str) or not call_id:
            continue
        result.append(
            {
                "id": call_id,
                "name": name,
                "arguments": _parse_arguments(function.get("arguments")),
                "raw_arguments": function.get("arguments"),
            }
        )
    return result


class FETIHACPAgent:
    """ACP agent implementation backed by FETIH sessions."""

    def __init__(self, session_manager: Optional[SessionManager] = None):
        self.session_manager = session_manager or SessionManager()
        self._conn = None
        # Set by the ACP runtime before the first request; the handler is the
        # one the router built, so keep the attribute name stable.
        self._use_unstable_protocol = True

    # -- lifecycle --------------------------------------------------------

    def on_connect(self, conn: Any) -> None:
        """Remember the client connection used for session updates."""
        self._conn = conn

    async def initialize(
        self,
        protocol_version: int,
        client_capabilities: Any = None,
        client_info: Any = None,
        **kwargs: Any,
    ) -> InitializeResponse:
        capabilities = AgentCapabilities(
            load_session=True,
            prompt_capabilities=None,
            session_capabilities=SessionCapabilities(
                close={},
                fork={},
                list={},
                resume={},
            ),
        )
        return InitializeResponse(
            protocol_version=acp.PROTOCOL_VERSION,
            agent_info=Implementation(name=AGENT_NAME, version=FETIH_VERSION),
            agent_capabilities=capabilities,
            auth_methods=build_auth_methods(),
        )

    async def authenticate(self, method_id: str, **kwargs: Any) -> Optional[AuthenticateResponse]:
        if not isinstance(method_id, str) or not method_id.strip():
            return None
        provider = detect_provider()
        if not provider:
            return None
        if method_id == TERMINAL_SETUP_AUTH_METHOD_ID:
            return AuthenticateResponse()
        if method_id.strip().lower() == provider.strip().lower():
            return AuthenticateResponse()
        return None

    # -- session lifecycle ------------------------------------------------

    async def new_session(
        self,
        cwd: str,
        mcp_servers: Any = None,
        **kwargs: Any,
    ) -> NewSessionResponse:
        state = self.session_manager.create_session(cwd=cwd)
        if mcp_servers:
            await self._register_session_mcp_servers(state, mcp_servers)
        await self._send_available_commands_update(state.session_id)
        return NewSessionResponse(
            session_id=state.session_id,
            modes=_mode_state(state.mode),
            models=self._build_model_state(state),
            config_options=None,
        )

    async def load_session(
        self,
        cwd: str,
        session_id: str,
        mcp_servers: Any = None,
        **kwargs: Any,
    ) -> Optional[LoadSessionResponse]:
        state = self.session_manager.get_session(session_id)
        if state is None:
            return None
        self.session_manager.update_cwd(session_id, cwd)
        if mcp_servers:
            await self._register_session_mcp_servers(state, mcp_servers)
        try:
            await self._replay_session_history(state)
        except Exception as exc:
            logger.warning("history replay raised during session/load: %s", exc)
        return LoadSessionResponse(
            modes=_mode_state(state.mode),
            models=self._build_model_state(state),
            config_options=None,
        )

    async def resume_session(
        self,
        cwd: str,
        session_id: str,
        mcp_servers: Any = None,
        **kwargs: Any,
    ) -> ResumeSessionResponse:
        state = self.session_manager.get_session(session_id)
        if state is None:
            state = self.session_manager.create_session(cwd=cwd, session_id=session_id)
        else:
            self.session_manager.update_cwd(session_id, cwd)
        if mcp_servers:
            await self._register_session_mcp_servers(state, mcp_servers)
        try:
            await self._replay_session_history(state)
        except Exception as exc:
            logger.warning("history replay raised during session/resume: %s", exc)
        return ResumeSessionResponse(
            modes=_mode_state(state.mode),
            models=self._build_model_state(state),
            config_options=None,
        )

    async def fork_session(
        self,
        cwd: str,
        session_id: str,
        mcp_servers: Any = None,
        **kwargs: Any,
    ) -> Optional[ForkSessionResponse]:
        forked = self.session_manager.fork_session(session_id, cwd=cwd)
        if forked is None:
            return None
        if mcp_servers:
            await self._register_session_mcp_servers(forked, mcp_servers)
        return ForkSessionResponse(
            session_id=forked.session_id,
            modes=_mode_state(forked.mode),
            models=self._build_model_state(forked),
            config_options=None,
        )

    async def close_session(self, session_id: str, **kwargs: Any) -> CloseSessionResponse:
        self.session_manager.remove_session(session_id)
        return CloseSessionResponse()

    async def cancel(self, session_id: str, **kwargs: Any) -> None:
        state = self.session_manager.get_session(session_id)
        if state is None:
            return
        state.cancel_event.set()

    # -- session listing --------------------------------------------------

    async def list_sessions(
        self,
        cursor: Optional[str] = None,
        cwd: Optional[str] = None,
        **kwargs: Any,
    ) -> ListSessionsResponse:
        entries = self.session_manager.list_sessions(cwd=cwd)
        if cursor:
            ids = [entry.get("session_id") for entry in entries]
            if cursor not in ids:
                return ListSessionsResponse(sessions=[], next_cursor=None)
            entries = entries[ids.index(cursor) + 1:]

        page = entries[:_LIST_SESSIONS_PAGE_SIZE]
        more = len(entries) > _LIST_SESSIONS_PAGE_SIZE
        sessions = [
            SessionInfo(
                session_id=str(entry.get("session_id") or ""),
                cwd=str(entry.get("cwd") or ""),
                title=entry.get("title"),
                updated_at=str(entry.get("updated_at")) if entry.get("updated_at") is not None else None,
            )
            for entry in page
        ]
        next_cursor = page[-1].get("session_id") if more and page else None
        return ListSessionsResponse(sessions=sessions, next_cursor=next_cursor)

    # -- session configuration -------------------------------------------

    async def set_session_mode(self, mode_id: str, session_id: str, **kwargs: Any) -> SetSessionModeResponse:
        state = self.session_manager.get_session(session_id)
        if state is not None and isinstance(mode_id, str) and mode_id:
            state.mode = mode_id
            state.edit_approval_policy = _MODE_TO_POLICY.get(mode_id, state.edit_approval_policy)
        return SetSessionModeResponse()

    async def set_config_option(
        self,
        config_id: str,
        session_id: str,
        value: Any,
        **kwargs: Any,
    ) -> SetSessionConfigOptionResponse:
        state = self.session_manager.get_session(session_id)
        if state is not None and config_id == "edit_approval_policy" and isinstance(value, str):
            state.edit_approval_policy = value
            mode = _POLICY_TO_MODE.get(value)
            if mode:
                state.mode = mode
        # Modes carry the approval policy for this agent, so no config options
        # are advertised.  The response keeps the shape clients expect.
        return SetSessionConfigOptionResponse(config_options=[])

    async def set_session_model(self, model_id: str, session_id: str, **kwargs: Any) -> Optional[SetSessionModelResponse]:
        state = self.session_manager.get_session(session_id)
        if state is None or not isinstance(model_id, str) or not model_id.strip():
            return None
        provider, separator, model = model_id.partition(":")
        if not separator:
            provider, model = None, model_id
        self._switch_model(state, provider, model)
        return SetSessionModelResponse()

    # -- prompt -----------------------------------------------------------

    async def prompt(
        self,
        prompt: Any,
        session_id: str,
        message_id: Optional[str] = None,
        **kwargs: Any,
    ) -> PromptResponse:
        state = self.session_manager.get_session(session_id)
        if state is None:
            return PromptResponse(stop_reason="refusal")

        text = _prompt_text(prompt).strip()
        if not text:
            return PromptResponse(stop_reason="end_turn")

        if text.startswith("/"):
            handled = self._handle_slash_command(text, state)
            if handled is not None:
                await self._send_message(state, handled)
                await self._send_usage_update(state)
                return PromptResponse(stop_reason="end_turn")

        if state.pending_notes:
            notes = "\n".join(state.pending_notes)
            state.pending_notes = []
            text = f"{text}\n\nQueued guidance:\n{notes}"

        return await self._run_turn(state, text)

    async def _run_turn(self, state: SessionState, text: str) -> PromptResponse:
        session_id = state.session_id
        conn = self._conn
        loop = asyncio.get_running_loop()
        state.cancel_event.clear()

        tool_call_ids: dict = {}
        tool_call_meta: dict = {}
        streamed: list = []

        stream_cb = events.make_message_cb(conn, session_id, loop)

        def on_delta(chunk: Any) -> None:
            if isinstance(chunk, str) and chunk:
                streamed.append(chunk)
            stream_cb(chunk)

        state.agent.tool_progress_callback = events.make_tool_progress_cb(
            conn, session_id, loop, tool_call_ids, tool_call_meta
        )
        state.agent.step_callback = events.make_step_cb(
            conn, session_id, loop, tool_call_ids, tool_call_meta
        )
        state.agent.stream_delta_callback = on_delta
        state.agent.reasoning_callback = events.make_thinking_cb(conn, session_id, loop)
        state.agent.thinking_callback = None

        result = await loop.run_in_executor(None, self._blocking_turn, state, text, conn, loop)

        if isinstance(result, dict):
            history = result.get("messages")
            if isinstance(history, list):
                state.history = history
        final_response = result.get("final_response") if isinstance(result, dict) else None

        streamed_text = "".join(streamed).strip()
        if isinstance(final_response, str) and final_response.strip() and not streamed_text:
            await self._send_message(state, final_response)

        self._maybe_auto_title(state, text, final_response, loop)
        await self._send_usage_update(state)

        if state.cancel_event.is_set():
            return PromptResponse(stop_reason="cancelled")

        usage = self._build_usage(result)
        return PromptResponse(stop_reason="end_turn", usage=usage)

    def _blocking_turn(self, state: SessionState, text: str, conn: Any, loop: Any) -> Any:
        """Run one synchronous agent turn on the executor thread."""
        from tools import terminal_tool

        from acp_adapter import edit_approval, permissions

        session_id = state.session_id
        tokens = None
        previous_env = os.environ.get("FETIH_INTERACTIVE")
        try:
            try:
                from gateway.session_context import set_session_vars

                tokens = set_session_vars(session_key=session_id)
            except Exception as exc:  # pragma: no cover - optional subsystem
                logger.debug("ACP session context could not be set: %s", exc)

            request_permission = getattr(conn, "request_permission", None)
            if callable(request_permission):
                terminal_tool.set_approval_callback(
                    permissions.make_approval_callback(request_permission, loop, session_id)
                )
                edit_approval.set_edit_approval_requester(
                    permissions.make_edit_approval_requester(request_permission, loop, session_id)
                )

            # Make the approval guards take the interactive path so the
            # callback above is actually consulted.
            os.environ["FETIH_INTERACTIVE"] = "1"

            return state.agent.run_conversation(
                text,
                conversation_history=list(state.history),
                task_id=session_id,
            )
        finally:
            if previous_env is None:
                os.environ.pop("FETIH_INTERACTIVE", None)
            else:
                os.environ["FETIH_INTERACTIVE"] = previous_env
            try:
                terminal_tool.set_approval_callback(None)
            except Exception:  # pragma: no cover - defensive
                pass
            try:
                edit_approval.clear_edit_approval_requester()
            except Exception:  # pragma: no cover - defensive
                pass
            if tokens is not None:
                try:
                    from gateway.session_context import clear_session_vars

                    clear_session_vars(tokens)
                except Exception:  # pragma: no cover - optional subsystem
                    pass

    # -- history replay ---------------------------------------------------

    async def _replay_session_history(self, state: SessionState) -> None:
        """Re-emit a persisted transcript as ACP session updates."""
        conn = self._conn
        if conn is None:
            return
        session_id = state.session_id
        pending: dict = {}

        for message in state.history or []:
            if not isinstance(message, dict):
                continue
            role = message.get("role")

            if role == "user":
                content = message.get("content")
                if isinstance(content, str) and content:
                    await self._replay(
                        session_id,
                        UserMessageChunk(
                            session_update="user_message_chunk",
                            content=TextContentBlock(type="text", text=content),
                        ),
                    )
                continue

            if role == "assistant":
                thought = _reasoning_text(message)
                if thought:
                    await self._replay_thought(session_id, thought)
                content = message.get("content")
                if isinstance(content, str) and content:
                    await self._replay(
                        session_id,
                        AgentMessageChunk(
                            session_update="agent_message_chunk",
                            content=TextContentBlock(type="text", text=content),
                        ),
                    )
                for call in _tool_calls_of(message):
                    pending[call["id"]] = call
                    await self._replay(
                        session_id,
                        build_tool_start(call["id"], call["name"], call["arguments"]),
                    )
                continue

            if role == "tool":
                call_id = message.get("tool_call_id")
                if not isinstance(call_id, str) or not call_id:
                    continue
                call = pending.get(call_id) or {}
                name = call.get("name")
                if not isinstance(name, str) or not name:
                    continue
                result = message.get("content")
                await self._replay(
                    session_id,
                    build_tool_complete(
                        call_id,
                        name,
                        result=result,
                        function_args=call.get("arguments"),
                    ),
                )
                if name == "todo":
                    await self._replay(
                        session_id,
                        events._build_plan_update_from_todo_result(result),
                    )

    async def _replay_thought(self, session_id: str, text: str) -> None:
        from acp.schema import AgentThoughtChunk

        await self._replay(
            session_id,
            AgentThoughtChunk(
                session_update="agent_thought_chunk",
                content=TextContentBlock(type="text", text=text),
            ),
        )

    async def _replay(self, session_id: str, update: Any) -> None:
        if self._conn is None:
            return
        try:
            await self._conn.session_update(session_id=session_id, update=update)
        except Exception as exc:
            logger.debug("ACP history replay update failed: %s", exc)

    # -- model state ------------------------------------------------------

    def _build_model_state(self, state: SessionState) -> Optional[SessionModelState]:
        provider = getattr(state.agent, "provider", None)
        if not isinstance(provider, str) or not provider:
            provider = state.provider
        model = getattr(state.agent, "model", None)
        if not isinstance(model, str) or not model:
            model = state.model
        if not isinstance(provider, str) or not provider:
            return None
        if not isinstance(model, str) or not model:
            return None

        try:
            from fetih_cli import models as fetih_models

            options = fetih_models.curated_models_for_provider(provider)
        except Exception as exc:
            logger.debug("ACP model list unavailable for %s: %s", provider, exc)
            options = []

        available: list[ModelInfo] = []
        seen = set()
        for name, hint in options or []:
            if not isinstance(name, str) or not name or name in seen:
                continue
            seen.add(name)
            description = f"Provider: {provider}"
            if isinstance(hint, str) and hint:
                description = f"{description} — {hint}"
            available.append(
                ModelInfo(model_id=f"{provider}:{name}", name=name, description=description)
            )
        if model not in seen:
            available.insert(
                0,
                ModelInfo(
                    model_id=f"{provider}:{model}",
                    name=model,
                    description=f"Provider: {provider} — current model",
                ),
            )
        return SessionModelState(
            available_models=available,
            current_model_id=f"{provider}:{model}",
        )

    def _switch_model(
        self,
        state: SessionState,
        provider: Optional[str],
        model: Optional[str],
    ) -> str:
        requested = provider or state.provider or None
        agent, info = self.session_manager.rebuild_agent(
            state, provider=requested, model=model
        )
        if agent is not None:
            state.agent = agent
        resolved_model = info.get("model") if isinstance(info, dict) else None
        state.model = resolved_model if isinstance(resolved_model, str) and resolved_model else model
        resolved_provider = info.get("provider") if isinstance(info, dict) else None
        if isinstance(resolved_provider, str) and resolved_provider:
            state.provider = resolved_provider
        base_url = info.get("base_url") if isinstance(info, dict) else None
        if isinstance(base_url, str):
            state.base_url = base_url
        return f"Switched to {state.model}\nProvider: {state.provider or 'unknown'}"

    # -- slash commands ---------------------------------------------------

    def _available_commands(self) -> list:
        commands = []
        for name, description, hint in _COMMAND_SPECS:
            payload = None
            if hint:
                payload = AvailableCommandInput(root=UnstructuredCommandInput(hint=hint))
            commands.append(
                AvailableCommand(name=name, description=description, input=payload)
            )
        return commands

    async def _send_available_commands_update(self, session_id: str) -> None:
        from acp.schema import AvailableCommandsUpdate

        if self._conn is None:
            return
        update = AvailableCommandsUpdate(
            session_update="available_commands_update",
            available_commands=self._available_commands(),
        )
        try:
            await self._conn.session_update(session_id=session_id, update=update)
        except Exception as exc:
            logger.debug("ACP available-commands update failed: %s", exc)

    async def _send_message(self, state: SessionState, text: str) -> None:
        if self._conn is None or not isinstance(text, str) or not text:
            return
        update = AgentMessageChunk(
            session_update="agent_message_chunk",
            content=TextContentBlock(type="text", text=text),
        )
        try:
            await self._conn.session_update(session_id=state.session_id, update=update)
        except Exception as exc:
            logger.debug("ACP message update failed: %s", exc)

    def _handle_slash_command(self, text: str, state: SessionState) -> Optional[str]:
        stripped = (text or "").strip()
        if not stripped.startswith("/"):
            return None
        head, _, rest = stripped.partition(" ")
        command = head.lower()
        argument = rest.strip()

        if command == "/help":
            return self._cmd_help()
        if command == "/model":
            return self._cmd_model(argument, state)
        if command == "/tools":
            return self._cmd_tools(state)
        if command == "/context":
            return self._cmd_context(state)
        if command == "/reset":
            return self._cmd_reset(state)
        if command == "/compact":
            return self._cmd_compact(state)
        if command == "/version":
            return f"FETIH ACP adapter {FETIH_VERSION}"
        if command in ("/steer", "/queue"):
            return self._cmd_queue(command, argument, state)
        return None

    def _cmd_help(self) -> str:
        lines = ["FETIH ACP commands:"]
        for name, description, hint in _COMMAND_SPECS:
            suffix = f" <{hint}>" if hint else ""
            lines.append(f"/{name}{suffix} — {description}")
        lines.append("")
        lines.append("Anything else is sent to the agent as a normal message.")
        return "\n".join(lines)

    def _cmd_model(self, argument: str, state: SessionState) -> str:
        if not argument:
            provider = getattr(state.agent, "provider", None) or state.provider or "unconfigured"
            model = getattr(state.agent, "model", None) or state.model or "unconfigured"
            return (
                f"Current model: {model}\n"
                f"Provider: {provider}\n"
                f"Switch with /model <provider>:<model> (or /model <model>)."
            )
        provider, separator, model = argument.partition(":")
        if not separator:
            provider, model = None, argument
        return self._switch_model(state, provider, model)

    def _cmd_tools(self, state: SessionState) -> str:
        tools = getattr(state.agent, "tools", None)
        if not isinstance(tools, list) or not tools:
            return "No tools are registered for this session."
        names = []
        for tool in tools:
            function = tool.get("function") if isinstance(tool, dict) else None
            name = function.get("name") if isinstance(function, dict) else None
            if isinstance(name, str) and name:
                names.append(name)
        return f"{len(names)} tools available:\n" + "\n".join(f"- {name}" for name in names)

    def _cmd_context(self, state: SessionState) -> str:
        history = state.history if isinstance(state.history, list) else []
        if not history:
            return "Context is empty — no messages in this session yet."

        roles: dict = {}
        for message in history:
            if isinstance(message, dict):
                role = message.get("role") or "unknown"
                roles[role] = roles.get(role, 0) + 1

        lines = [f"Context: {len(history)} messages"]
        for role, count in sorted(roles.items()):
            lines.append(f"  {role}: {count}")

        compressor = getattr(state.agent, "context_compressor", None)
        size = getattr(compressor, "context_length", None)
        threshold = getattr(compressor, "threshold_tokens", None)
        if not isinstance(size, int) or size <= 0:
            return "\n".join(lines)

        used = self._estimate_tokens(state, history)
        lines.append(
            f"Context usage: ~{used:,} / {size:,} tokens ({100.0 * used / size:.1f}%)"
        )

        if not isinstance(threshold, int) or threshold <= 0:
            return "\n".join(lines)

        threshold_pct = 100.0 * threshold / size
        if used >= threshold:
            lines.append(
                f"Compression: due now (threshold ~{threshold:,}, {threshold_pct:.0f}%). Run /compact."
            )
        else:
            lines.append(
                f"Compression: ~{threshold - used:,} tokens until threshold "
                f"(~{threshold:,}, {threshold_pct:.0f}%)"
            )
            lines.append("Tip: run /compact to compress the conversation now.")
        return "\n".join(lines)

    def _estimate_tokens(self, state: SessionState, messages: list) -> int:
        try:
            from agent import model_metadata

            system_prompt = getattr(state.agent, "_cached_system_prompt", None)
            tools = getattr(state.agent, "tools", None)
            return _as_int(
                model_metadata.estimate_request_tokens_rough(
                    messages,
                    system_prompt=system_prompt if isinstance(system_prompt, str) else "",
                    tools=tools if isinstance(tools, list) else None,
                )
            )
        except Exception as exc:
            logger.debug("ACP token estimate failed: %s", exc)
            return 0

    def _cmd_reset(self, state: SessionState) -> str:
        state.history = []
        try:
            self.session_manager.save_session(state.session_id)
        except Exception as exc:
            logger.debug("ACP session save after /reset failed: %s", exc)
        return "Conversation history cleared."

    def _cmd_compact(self, state: SessionState) -> str:
        history = state.history if isinstance(state.history, list) else []
        if not history:
            return "Context is already empty — nothing to compress."

        try:
            from agent import model_metadata
        except Exception as exc:  # pragma: no cover - import guard
            logger.warning("ACP /compact unavailable: %s", exc)
            return "Compression is unavailable in this build."

        before = _as_int(model_metadata.estimate_request_tokens_rough(history))
        system_prompt = getattr(state.agent, "_cached_system_prompt", None)

        # The compressor writes to the session database itself; detach it so a
        # manual /compact does not double-persist the rewrite.
        saved_db = getattr(state.agent, "_session_db", None)
        try:
            state.agent._session_db = None
            compressed, _new_system = state.agent._compress_context(
                history,
                system_prompt,
                approx_tokens=before,
                task_id=state.session_id,
            )
        except Exception as exc:
            logger.warning("ACP /compact failed: %s", exc)
            return f"Compression failed: {exc}"
        finally:
            state.agent._session_db = saved_db

        if not isinstance(compressed, list):
            return "Compression produced no result; nothing changed."

        state.history = compressed
        after = _as_int(model_metadata.estimate_request_tokens_rough(compressed))
        try:
            self.session_manager.save_session(state.session_id)
        except Exception as exc:
            logger.debug("ACP session save after /compact failed: %s", exc)
        return (
            f"Context compressed: {len(history)} -> {len(compressed)} messages "
            f"(~{before:,} -> ~{after:,} tokens)"
        )

    def _cmd_queue(self, command: str, argument: str, state: SessionState) -> str:
        if not argument:
            kind = "guidance" if command == "/steer" else "message"
            return f"Usage: {command} <{kind} text>"
        state.pending_notes.append(argument)
        return f"Queued for the next turn ({len(state.pending_notes)} pending)."

    # -- usage ------------------------------------------------------------

    def _build_usage(self, result: Any) -> Optional[Usage]:
        if not isinstance(result, dict):
            return None
        input_tokens = _as_int(result.get("prompt_tokens"))
        output_tokens = _as_int(result.get("completion_tokens"))
        total_tokens = _as_int(result.get("total_tokens"))
        if not any((input_tokens, output_tokens, total_tokens)):
            return None
        return Usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens or input_tokens + output_tokens,
            thought_tokens=_as_int(result.get("reasoning_tokens")),
            cached_read_tokens=_as_int(result.get("cache_read_tokens")),
            cached_write_tokens=_as_int(result.get("cache_write_tokens")),
        )

    def _build_usage_update(self, state: SessionState) -> Optional[UsageUpdate]:
        compressor = getattr(state.agent, "context_compressor", None)
        size = _as_int(getattr(compressor, "context_length", 0))
        if size <= 0:
            return None
        history = state.history if isinstance(state.history, list) else []
        used = self._estimate_tokens(state, history)
        return UsageUpdate(
            session_update="usage_update",
            size=size,
            used=max(used, 0),
        )

    async def _send_usage_update(self, state: SessionState) -> None:
        if self._conn is None:
            return
        try:
            update = self._build_usage_update(state)
        except Exception as exc:
            logger.debug("ACP usage update could not be built: %s", exc)
            return
        if update is None:
            return
        try:
            await self._conn.session_update(session_id=state.session_id, update=update)
        except Exception as exc:
            logger.debug("ACP usage update failed: %s", exc)

    # -- titles -----------------------------------------------------------

    def _maybe_auto_title(
        self,
        state: SessionState,
        user_text: str,
        final_response: Any,
        loop: Any,
    ) -> None:
        if not isinstance(final_response, str) or not final_response.strip():
            return
        try:
            from agent import title_generator

            db = self.session_manager.get_db()
            if db is None:
                return

            def title_callback(title: Any) -> None:
                if isinstance(title, str) and title.strip():
                    state.title = title
                    events._send_update(
                        self._conn,
                        state.session_id,
                        loop,
                        SessionInfoUpdate(
                            session_update="session_info_update",
                            title=title,
                        ),
                    )

            title_generator.maybe_auto_title(
                db,
                state.session_id,
                user_text,
                final_response,
                state.history,
                title_callback=title_callback,
            )
        except Exception as exc:
            logger.debug("ACP auto-title failed: %s", exc)

    # -- MCP servers ------------------------------------------------------

    async def _register_session_mcp_servers(self, state: SessionState, mcp_servers: Any) -> None:
        """Convert ACP MCP servers into FETIH config and refresh the agent."""
        if not mcp_servers:
            return

        config: dict = {}
        for server in mcp_servers:
            name = getattr(server, "name", None)
            if not isinstance(name, str) or not name:
                continue
            if isinstance(server, McpServerStdio):
                env = {}
                for variable in getattr(server, "env", None) or []:
                    key = getattr(variable, "name", None)
                    if isinstance(key, str) and key:
                        env[key] = getattr(variable, "value", "")
                config[name] = {
                    "command": getattr(server, "command", None),
                    "args": list(getattr(server, "args", None) or []),
                    "env": env,
                }
            elif isinstance(server, McpServerHttp):
                headers = {}
                for header in getattr(server, "headers", None) or []:
                    key = getattr(header, "name", None)
                    if isinstance(key, str) and key:
                        headers[key] = getattr(header, "value", "")
                config[name] = {
                    "url": getattr(server, "url", None),
                    "headers": headers,
                }

        if not config:
            return

        try:
            from tools import mcp_tool

            mcp_tool.register_mcp_servers(config)
        except Exception as exc:
            logger.warning("ACP MCP server registration failed: %s", exc)

        self._refresh_agent_tools(state, list(config))

    def _refresh_agent_tools(self, state: SessionState, server_names: list) -> None:
        agent = state.agent
        enabled = getattr(agent, "enabled_toolsets", None)
        enabled_toolsets = list(enabled) if isinstance(enabled, list) and enabled else [_DEFAULT_TOOLSET]
        for name in server_names:
            toolset = f"mcp-{name}"
            if toolset not in enabled_toolsets:
                enabled_toolsets.append(toolset)

        disabled = getattr(agent, "disabled_toolsets", None)
        disabled_toolsets = list(disabled) if isinstance(disabled, list) else None

        try:
            from model_tools import get_tool_definitions

            tools = get_tool_definitions(
                enabled_toolsets=enabled_toolsets,
                disabled_toolsets=disabled_toolsets,
                quiet_mode=True,
            )
        except Exception as exc:
            logger.warning("ACP tool surface refresh failed: %s", exc)
            return

        agent.enabled_toolsets = enabled_toolsets
        agent.disabled_toolsets = disabled_toolsets
        agent.tools = tools
        names = set()
        for tool in tools or []:
            function = tool.get("function") if isinstance(tool, dict) else None
            name = function.get("name") if isinstance(function, dict) else None
            if isinstance(name, str) and name:
                names.add(name)
        agent.valid_tool_names = names

        invalidate = getattr(agent, "_invalidate_system_prompt", None)
        if callable(invalidate):
            try:
                invalidate()
            except Exception as exc:
                logger.debug("ACP system prompt invalidation failed: %s", exc)


__all__ = ["FETIHACPAgent", "FETIH_VERSION"]

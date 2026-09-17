"""ACP session lifecycle: in-memory state, persistence, and cwd translation.

An ACP session is a conversation owned by the client (Zed, VS Code).  It maps
onto a FETIH agent run plus a ``SessionDB`` row (``source='acp'``), so a client
that reconnects later can reload the transcript.

Two things this module is careful about:

* **cwd translation.**  The client sends the workspace root in *its* platform's
  form.  On WSL the tools run inside Linux, so ``E:\\Projects`` becomes
  ``/mnt/e/Projects`` before it reaches the terminal tool.
* **staying hermetic.**  The database path is resolved lazily from
  ``FETIH_HOME`` at call time so every session lands in the caller's home.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import fetih_constants

logger = logging.getLogger(__name__)

_DEFAULT_TOOLSET = "fetih-acp"
_DB_LIST_LIMIT = 200
_WINDOWS_DRIVE_RE = re.compile(r"^([A-Za-z]):[/\\](.*)$")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)$")


@dataclass
class SessionState:
    """Live state for one ACP session."""

    session_id: str
    cwd: Optional[str] = None
    history: list = field(default_factory=list)
    agent: Any = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    model: Optional[str] = None
    mode: str = "default"
    updated_at: float = field(default_factory=time.time)
    provider: Optional[str] = None
    base_url: Optional[str] = None
    api_mode: Optional[str] = None
    title: Optional[str] = None
    edit_approval_policy: str = "ask"
    pending_notes: list = field(default_factory=list)


def _translate_acp_cwd(cwd: Optional[str]) -> Optional[str]:
    """Translate a client cwd into the path form FETIH's tools expect.

    Only Windows drive paths change, and only on WSL, where the terminal tool
    runs inside the Linux mount namespace.
    """
    if not cwd or not isinstance(cwd, str):
        return cwd
    if not fetih_constants.is_wsl():
        return cwd
    text = cwd.strip()
    if text.startswith("/mnt/"):
        return text
    match = _WINDOWS_DRIVE_RE.match(text)
    if not match:
        return cwd
    drive, rest = match.group(1).lower(), match.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def _register_task_cwd(task_id: str, cwd: Optional[str]) -> None:
    """Point the terminal tool at *cwd* for this session's tasks."""
    if not task_id or not cwd:
        return
    try:
        from tools.terminal_tool import register_task_env_overrides

        register_task_env_overrides(task_id, {"cwd": _translate_acp_cwd(cwd)})
    except Exception as exc:
        logger.debug("could not register task cwd for %s: %s", task_id, exc)


def _canonical_cwd(path: Optional[str]) -> str:
    """Canonicalize a cwd so Windows and WSL spellings compare equal."""
    if not path or not isinstance(path, str):
        return ""
    text = path.strip().replace("\\", "/")
    match = _WINDOWS_DRIVE_RE.match(text)
    if match:
        text = f"/mnt/{match.group(1).lower()}/{match.group(2)}"
    else:
        mnt = _MNT_RE.match(text)
        if mnt:
            text = f"/mnt/{mnt.group(1).lower()}/{mnt.group(2)}"
    text = text.rstrip("/") or "/"
    return text.lower()


def _preview_from_history(history: list) -> str:
    for message in history or []:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if not isinstance(content, str):
            continue
        text = content.strip()
        if text:
            return text[:60] + ("..." if len(text) > 60 else "")
    return ""


def _safe_json(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _is_enabled_flag(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    if isinstance(value, (int, float)):
        return bool(value)
    return True


def _default_toolsets(config: dict) -> list:
    """Baseline toolsets for an ACP session, including configured MCP servers."""
    toolsets = [_DEFAULT_TOOLSET]
    servers = config.get("mcp_servers") if isinstance(config, dict) else None
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(name, str) or not name:
                continue
            if isinstance(spec, dict) and not _is_enabled_flag(spec.get("enabled", True)):
                continue
            toolsets.append(f"mcp-{name}")
    return toolsets


def _stderr_print(*args: Any, **kwargs: Any) -> None:
    """Print to stderr — stdout is reserved for the ACP JSON-RPC stream."""
    kwargs.setdefault("file", os.sys.stderr)
    print(*args, **kwargs)


class SessionManager:
    """Owns every ACP session in this process."""

    def __init__(self, agent_factory: Optional[Callable] = None, db: Any = None):
        self._agent_factory = agent_factory
        self._db = db
        self._db_lock = threading.Lock()
        self._lock = threading.RLock()
        self._sessions: dict = {}

    # -- database ---------------------------------------------------------

    def _get_db(self):
        if self._db is not None:
            return self._db
        with self._db_lock:
            if self._db is not None:
                return self._db
            try:
                from fetih_state import SessionDB

                db_path = Path(fetih_constants.get_fetih_home()) / "state.db"
                self._db = SessionDB(db_path)
            except Exception as exc:
                logger.warning("ACP session database unavailable: %s", exc)
                return None
        return self._db

    # -- agent construction ----------------------------------------------

    def get_db(self):
        """Return the session database, creating it on first use."""
        return self._get_db()

    def rebuild_agent(self, state: SessionState, *, provider=None, model=None):
        """Build a replacement agent for *state*; returns ``(agent, info)``."""
        return self._spawn_agent(
            cwd=state.cwd,
            session_id=state.session_id,
            provider=provider,
            model=model,
        )

    def _spawn_agent(
        self,
        *,
        cwd: Optional[str] = None,
        session_id: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Create an agent for a session; returns ``(agent, runtime_info)``."""
        if self._agent_factory is not None:
            return self._agent_factory(), {"provider": provider, "model": model}
        return self._build_agent(
            cwd=cwd, session_id=session_id, provider=provider, model=model
        )

    def _build_agent(
        self,
        *,
        cwd: Optional[str] = None,
        session_id: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        config: dict = {}
        try:
            from fetih_cli import config as fetih_config

            loaded = fetih_config.load_config()
            if isinstance(loaded, dict):
                config = loaded
        except Exception as exc:
            logger.debug("ACP config load failed: %s", exc)

        model_config = config.get("model")
        if not isinstance(model_config, dict):
            model_config = {}

        requested = provider
        if not requested:
            configured = model_config.get("provider")
            requested = configured if isinstance(configured, str) else None

        runtime: dict = {}
        try:
            from fetih_cli import runtime_provider as runtime_provider_module

            resolved = runtime_provider_module.resolve_runtime_provider(
                requested=requested, target_model=model
            )
            if isinstance(resolved, dict):
                runtime = resolved
        except Exception as exc:
            logger.debug("ACP runtime provider resolution failed: %s", exc)

        resolved_provider = runtime.get("provider")
        if not isinstance(resolved_provider, str) or not resolved_provider:
            resolved_provider = requested

        model_name = model
        if not model_name:
            configured_model = model_config.get("default")
            model_name = configured_model if isinstance(configured_model, str) else None

        enabled_toolsets = _default_toolsets(config)

        import run_agent

        agent = run_agent.AIAgent(
            model=model_name or "",
            provider=resolved_provider,
            api_key=runtime.get("api_key"),
            base_url=runtime.get("base_url"),
            api_mode=runtime.get("api_mode"),
            enabled_toolsets=enabled_toolsets,
            disabled_toolsets=None,
            session_id=session_id,
            quiet_mode=True,
        )

        try:
            agent._print_fn = _stderr_print
        except Exception:  # pragma: no cover - exotic agent implementations
            logger.debug("could not route agent output to stderr")

        info = {
            "provider": resolved_provider,
            "model": model_name,
            "base_url": runtime.get("base_url"),
            "api_mode": runtime.get("api_mode"),
            "enabled_toolsets": enabled_toolsets,
        }
        return agent, info

    # -- create / restore -------------------------------------------------

    def create_session(
        self,
        cwd: Optional[str] = None,
        session_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SessionState:
        sid = session_id or f"acp-{uuid.uuid4().hex[:16]}"
        translated_cwd = _translate_acp_cwd(cwd)

        agent, info = self._spawn_agent(cwd=translated_cwd, session_id=sid)
        state = SessionState(
            session_id=sid,
            cwd=translated_cwd,
            agent=agent,
            updated_at=time.time(),
        )
        self._apply_runtime_info(state, info)

        with self._lock:
            self._sessions[sid] = state

        self._create_db_row(state)
        _register_task_cwd(sid, translated_cwd)
        return state

    def _apply_runtime_info(self, state: SessionState, info: dict) -> None:
        if not isinstance(info, dict):
            return
        provider = info.get("provider")
        if isinstance(provider, str) and provider:
            state.provider = provider
        model = info.get("model")
        if isinstance(model, str) and model:
            state.model = model
        base_url = info.get("base_url")
        if isinstance(base_url, str):
            state.base_url = base_url
        api_mode = info.get("api_mode")
        if isinstance(api_mode, str):
            state.api_mode = api_mode

    def _session_metadata(self, state: SessionState) -> dict:
        payload = {
            "cwd": state.cwd,
            "provider": state.provider,
            "model": state.model,
            "base_url": state.base_url,
            "api_mode": state.api_mode,
            "edit_approval_policy": state.edit_approval_policy,
        }
        # Only persist values we own; never introspect the agent (it may be a
        # test double, or carry values that are not JSON-serializable).
        return {k: v for k, v in payload.items() if isinstance(v, (str, type(None))) and v is not None or k == "cwd"}

    def _create_db_row(self, state: SessionState, parent_session_id: Optional[str] = None) -> None:
        db = self._get_db()
        if db is None:
            return
        try:
            db.create_session(
                session_id=state.session_id,
                source="acp",
                model=state.model,
                model_config=self._session_metadata(state),
                parent_session_id=parent_session_id,
            )
        except Exception as exc:
            logger.warning("ACP session could not be persisted: %s", exc)

    def _persist_metadata(self, state: SessionState) -> None:
        db = self._get_db()
        if db is None:
            return
        payload = json.dumps(self._session_metadata(state))
        try:
            def _do(conn):
                conn.execute(
                    "UPDATE sessions SET model_config = ?, model = ? WHERE id = ?",
                    (payload, state.model, state.session_id),
                )

            db._execute_write(_do)
        except Exception as exc:
            logger.debug("ACP session metadata update failed: %s", exc)

    def _restore_session(self, session_id: str) -> Optional[SessionState]:
        db = self._get_db()
        if db is None:
            return None
        try:
            row = db.get_session(session_id)
        except Exception as exc:
            logger.debug("ACP session lookup failed: %s", exc)
            return None
        if not row or row.get("source") != "acp":
            return None

        metadata = _safe_json(row.get("model_config"))
        try:
            history = db.get_messages_as_conversation(session_id) or []
        except Exception as exc:
            logger.warning("ACP session history could not be restored: %s", exc)
            history = []

        stored_model = row.get("model")
        if not isinstance(stored_model, str):
            stored_model = None

        agent, info = self._spawn_agent(
            cwd=metadata.get("cwd"),
            session_id=session_id,
            provider=metadata.get("provider"),
            model=metadata.get("model") or stored_model,
        )
        state = SessionState(
            session_id=session_id,
            cwd=metadata.get("cwd"),
            history=history,
            agent=agent,
            updated_at=time.time(),
            title=row.get("title"),
        )
        self._apply_runtime_info(state, info)
        if isinstance(metadata.get("base_url"), str) and metadata.get("base_url"):
            state.base_url = metadata["base_url"]
        if isinstance(metadata.get("edit_approval_policy"), str):
            state.edit_approval_policy = metadata["edit_approval_policy"]

        with self._lock:
            existing = self._sessions.get(session_id)
            if existing is not None:
                return existing
            self._sessions[session_id] = state
        return state

    def get_session(self, session_id: Optional[str]) -> Optional[SessionState]:
        if not session_id or not isinstance(session_id, str):
            return None
        with self._lock:
            state = self._sessions.get(session_id)
        if state is not None:
            return state
        return self._restore_session(session_id)

    # -- mutation ---------------------------------------------------------

    def save_session(self, session_id: str) -> None:
        """Persist the transcript and metadata for *session_id*."""
        with self._lock:
            state = self._sessions.get(session_id)
        if state is None:
            return

        state.updated_at = time.time()
        db = self._get_db()
        if db is None:
            return
        try:
            # replace_messages() is a single transaction: a non-serializable
            # message rolls the whole write back, so the previously persisted
            # transcript survives rather than being clobbered.
            db.replace_messages(session_id, list(state.history))
        except Exception as exc:
            logger.warning("ACP session transcript could not be saved: %s", exc)
        self._persist_metadata(state)

    def update_cwd(self, session_id: str, cwd: Optional[str]) -> Optional[SessionState]:
        state = self.get_session(session_id)
        if state is None:
            return None
        state.cwd = _translate_acp_cwd(cwd)
        state.updated_at = time.time()
        self._persist_metadata(state)
        if state.cwd:
            _register_task_cwd(session_id, state.cwd)
        return state

    def fork_session(
        self,
        session_id: str,
        cwd: Optional[str] = None,
        session_id_new: Optional[str] = None,
    ) -> Optional[SessionState]:
        source = self.get_session(session_id)
        if source is None:
            return None

        forked_cwd = _translate_acp_cwd(cwd) if cwd else source.cwd
        fork_id = session_id_new or f"acp-{uuid.uuid4().hex[:16]}"
        agent, info = self._spawn_agent(
            cwd=forked_cwd, session_id=fork_id, provider=source.provider, model=source.model
        )
        forked = SessionState(
            session_id=fork_id,
            cwd=forked_cwd,
            history=json.loads(json.dumps(source.history, default=str)),
            agent=agent,
            updated_at=time.time(),
            model=source.model,
            provider=source.provider,
        )
        self._apply_runtime_info(forked, info)
        with self._lock:
            self._sessions[fork_id] = forked

        self._create_db_row(forked, parent_session_id=source.session_id)
        _register_task_cwd(fork_id, forked_cwd)
        return forked

    def remove_session(self, session_id: str) -> bool:
        with self._lock:
            removed = self._sessions.pop(session_id, None)
        db = self._get_db()
        deleted = False
        if db is not None:
            try:
                deleted = bool(db.delete_session(session_id))
            except Exception as exc:
                logger.debug("ACP session delete failed: %s", exc)
        return removed is not None or deleted

    def cleanup(self) -> None:
        """Drop every session this manager owns (memory and database)."""
        with self._lock:
            states = list(self._sessions.values())
            self._sessions.clear()

        db = self._get_db()
        if db is None:
            return
        session_ids = [state.session_id for state in states]
        try:
            rows = db.list_sessions_rich(source="acp", limit=1000, include_children=True)
            for row in rows or []:
                sid = row.get("id")
                if sid and sid not in session_ids:
                    session_ids.append(sid)
        except Exception as exc:
            logger.debug("ACP session listing during cleanup failed: %s", exc)
        for sid in session_ids:
            try:
                db.delete_session(sid)
            except Exception as exc:
                logger.debug("ACP session delete failed for %s: %s", sid, exc)

    # -- listing ----------------------------------------------------------

    def list_sessions(self, cwd: Optional[str] = None) -> list:
        """Return listing entries for every non-empty ACP session."""
        entries: dict = {}

        db = self._get_db()
        if db is not None:
            try:
                rows = db.list_sessions_rich(
                    source="acp", limit=_DB_LIST_LIMIT, order_by_last_active=True
                )
            except Exception as exc:
                logger.debug("ACP session listing failed: %s", exc)
                rows = []
            for row in rows or []:
                sid = row.get("id")
                if not sid:
                    continue
                metadata = _safe_json(row.get("model_config"))
                entries[sid] = {
                    "session_id": sid,
                    "cwd": metadata.get("cwd"),
                    "title": row.get("title") or row.get("preview") or "",
                    "updated_at": row.get("last_active") or row.get("started_at"),
                    "message_count": row.get("message_count") or 0,
                }

        with self._lock:
            states = list(self._sessions.values())
        for state in states:
            if not state.history:
                continue
            previous = entries.get(state.session_id) or {}
            entries[state.session_id] = {
                "session_id": state.session_id,
                "cwd": state.cwd,
                "title": previous.get("title") or _preview_from_history(state.history),
                "updated_at": state.updated_at,
                "message_count": len(state.history),
            }

        items = [entry for entry in entries.values() if entry.get("message_count")]
        if cwd is not None:
            target = _canonical_cwd(cwd)
            items = [entry for entry in items if _canonical_cwd(entry.get("cwd")) == target]
        items.sort(key=lambda entry: entry.get("updated_at") or 0, reverse=True)
        return items


__all__ = ["SessionManager", "SessionState"]

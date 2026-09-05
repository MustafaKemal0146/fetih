"""Method registry and dispatch for the FETİH Masaüstü Köprüsü.

Every RPC method lives here exactly once.  Both transports
(``transport.serve_stdio`` and ``transport.serve_websocket``) call
:meth:`BridgeServer.handle_line`, so the wire behaviour is identical no
matter how the desktop app attached itself.

The agent is the *real* one: ``run_agent.AIAgent``, built the same way
``fetih_cli/oneshot.py`` builds it (config → runtime provider → toolsets),
and driven with its real streaming/tool callbacks.  Nothing here is mocked.

Security
--------
* WebSocket connections start unauthenticated; the first accepted method is
  ``bridge.authenticate``.  Everything else returns ``UNAUTHORIZED``.
* stdio connections are pre-authenticated — the parent process spawned us.
* Secrets are never returned: ``config.get`` redacts anything whose key looks
  like a credential, and ``providers.list`` reports only whether a key is
  *present*, never its value.
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import PROTOCOL_VERSION
from .protocol import (
    AGENT_ERROR,
    CANCELLED,
    CONFIG_ERROR,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    SESSION_BUSY,
    SESSION_NOT_FOUND,
    UNAUTHORIZED,
    BridgeError,
    decode,
    error,
    event,
    response,
)

#: Config keys whose *values* must never cross the wire.
_SECRET_HINTS = ("api_key", "apikey", "token", "secret", "password", "passwd", "credential")

#: Methods callable before ``bridge.authenticate`` succeeds.
_PREAUTH_METHODS = {"bridge.authenticate", "bridge.ping", "bridge.capabilities"}


def _looks_secret(key: str) -> bool:
    k = str(key).lower()
    return any(hint in k for hint in _SECRET_HINTS)


def _redact(value: Any, key: str = "") -> Any:
    """Deep-copy ``value`` replacing credential-shaped leaves with a marker."""
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if key and _looks_secret(key) and isinstance(value, str) and value:
        # Env-var *references* (``${GROQ_API_KEY}``) are names, not secrets.
        if value.startswith("${") and value.endswith("}"):
            return value
        return "<redacted>"
    return value


class BridgeSession:
    """One conversation, backed by a live ``AIAgent`` instance."""

    def __init__(self, session_id: str, agent, *, model: str, provider: str, cwd: str):
        self.id = session_id
        self.agent = agent
        self.model = model
        self.provider = provider
        self.cwd = cwd
        self.created_at = time.time()
        self.busy = False
        self.turns = 0
        self.thread_id: Optional[int] = None

    def snapshot(self) -> Dict[str, Any]:
        return {
            "session_id": self.id,
            "model": self.model,
            "provider": self.provider,
            "cwd": self.cwd,
            "created_at": self.created_at,
            "busy": self.busy,
            "turns": self.turns,
        }


class BridgeServer:
    """Transport-agnostic JSON-RPC dispatcher."""

    def __init__(self, *, token: str = "", require_auth: bool = True):
        self.token = token
        self.require_auth = require_auth
        self.sessions: Dict[str, BridgeSession] = {}
        self._connections: Dict[int, asyncio.AbstractEventLoop] = {}
        self._conn_objs: List[Any] = []
        self._methods: Dict[str, Callable[..., Any]] = {}
        self._started = time.time()
        self._register_methods()

    # ── connection bookkeeping ──────────────────────────────────────────

    def attach(self, conn, loop: asyncio.AbstractEventLoop) -> None:
        self._connections[id(conn)] = loop
        self._conn_objs.append(conn)

    def detach(self, conn) -> None:
        self._connections.pop(id(conn), None)
        try:
            self._conn_objs.remove(conn)
        except ValueError:
            pass

    def loop_for(self, conn) -> Optional[asyncio.AbstractEventLoop]:
        return self._connections.get(id(conn))

    def ready_frame(self) -> Dict[str, Any]:
        return event(
            "bridge.ready",
            {
                "protocol_version": PROTOCOL_VERSION,
                "auth_required": bool(self.require_auth and self.token),
                "pid": os.getpid(),
            },
        )

    # ── dispatch ────────────────────────────────────────────────────────

    async def handle_line(self, conn, line: str) -> None:
        try:
            frame = decode(line)
        except Exception as exc:
            await conn.send_frame(error(None, PARSE_ERROR, f"malformed frame: {exc}"))
            return

        rid = frame.get("id")
        method = frame.get("method")

        if not isinstance(method, str) or not method:
            await conn.send_frame(error(rid, INVALID_REQUEST, "missing 'method'"))
            return

        # ``or {}`` would swallow a wrong-typed empty container ([] is falsy),
        # so test for absence explicitly before type-checking.
        params = frame.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            await conn.send_frame(error(rid, INVALID_PARAMS, "'params' must be an object"))
            return

        handler = self._methods.get(method)
        if handler is None:
            await conn.send_frame(error(rid, METHOD_NOT_FOUND, f"unknown method: {method}"))
            return

        if (
            self.require_auth
            and self.token
            and not conn.authenticated
            and method not in _PREAUTH_METHODS
        ):
            await conn.send_frame(
                error(rid, UNAUTHORIZED, "call bridge.authenticate first")
            )
            return

        try:
            result = handler(conn, params)
            if asyncio.iscoroutine(result):
                result = await result
        except BridgeError as exc:
            await conn.send_frame(error(rid, exc.code, exc.message, exc.data))
            return
        except Exception as exc:  # pragma: no cover - defensive
            await conn.send_frame(
                error(rid, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
            )
            return

        # A frame with no ``id`` is a notification — no reply is expected.
        if rid is not None:
            await conn.send_frame(response(rid, result))

    # ── method registry ─────────────────────────────────────────────────

    def _register_methods(self) -> None:
        self._methods.update(
            {
                "bridge.ping": self._m_ping,
                "bridge.authenticate": self._m_authenticate,
                "bridge.capabilities": self._m_capabilities,
                "session.new": self._m_session_new,
                "session.list": self._m_session_list,
                "session.close": self._m_session_close,
                "session.send": self._m_session_send,
                "session.cancel": self._m_session_cancel,
                "config.get": self._m_config_get,
                "config.set": self._m_config_set,
                "providers.list": self._m_providers_list,
                "skills.list": self._m_skills_list,
                "diagnostics.info": self._m_diagnostics_info,
                "shell.status": self._m_shell_status,
                "shell.ensure_user": self._m_shell_ensure_user,
                "system.reset_configuration": self._m_system_reset_configuration,
                "system.wipe_all_data": self._m_system_wipe_all_data,
            }
        )

    # ── bridge.* ────────────────────────────────────────────────────────

    def _m_ping(self, conn, params):
        return {"pong": True, "time": time.time(), "uptime_s": time.time() - self._started}

    def _m_authenticate(self, conn, params):
        if not (self.require_auth and self.token):
            conn.authenticated = True
            return {"authenticated": True, "protocol_version": PROTOCOL_VERSION}
        supplied = str(params.get("token") or "")
        # Constant-time-ish comparison; the token is short-lived and loopback-only.
        import hmac

        if not hmac.compare_digest(supplied, self.token):
            raise BridgeError(UNAUTHORIZED, "invalid token")
        conn.authenticated = True
        return {"authenticated": True, "protocol_version": PROTOCOL_VERSION}

    def _m_capabilities(self, conn, params):
        return {
            "protocol_version": PROTOCOL_VERSION,
            "min_supported_version": 1,
            "max_supported_version": PROTOCOL_VERSION,
            "auth_required": bool(self.require_auth and self.token),
            "authenticated": bool(conn.authenticated),
            "transport": conn.kind,
            "fetih_version": _fetih_version(),
            "methods": sorted(self._methods),
            "events": [
                "bridge.ready",
                "session.delta",
                "session.tool_call",
                "session.tool_result",
                "session.done",
                "session.error",
            ],
        }

    # ── session.* ───────────────────────────────────────────────────────

    def _m_session_new(self, conn, params):
        session = self._build_session(**_session_params(params))
        self.sessions[session.id] = session
        return session.snapshot()

    def _m_session_list(self, conn, params):
        return {"sessions": [s.snapshot() for s in self.sessions.values()]}

    def _m_session_close(self, conn, params):
        sid = str(params.get("session_id") or "")
        session = self.sessions.pop(sid, None)
        if session is None:
            raise BridgeError(SESSION_NOT_FOUND, f"no such session: {sid}")
        return {"closed": True, "session_id": sid}

    async def _m_session_send(self, conn, params):
        message = params.get("message")
        if not isinstance(message, str) or not message.strip():
            raise BridgeError(INVALID_PARAMS, "'message' must be a non-empty string")

        sid = params.get("session_id")
        if sid:
            session = self.sessions.get(str(sid))
            if session is None:
                raise BridgeError(SESSION_NOT_FOUND, f"no such session: {sid}")
        else:
            session = self._build_session(**_session_params(params))
            self.sessions[session.id] = session

        if session.busy:
            raise BridgeError(SESSION_BUSY, f"session {session.id} is already running a turn")

        loop = self.loop_for(conn) or asyncio.get_running_loop()
        stream = params.get("stream", True) is not False

        session.busy = True
        started = time.perf_counter()
        tool_calls: List[Dict[str, Any]] = []

        # These callbacks fire on the worker thread; every emit is marshalled
        # back onto the event loop via Connection.emit_threadsafe.
        def on_delta(text: str) -> None:
            if stream and text:
                conn.emit_threadsafe(
                    loop, event("session.delta", {"session_id": session.id, "text": text})
                )

        def on_tool_start(call_id, name, args) -> None:
            tool_calls.append({"id": str(call_id), "name": name})
            conn.emit_threadsafe(
                loop,
                event(
                    "session.tool_call",
                    {
                        "session_id": session.id,
                        "id": str(call_id),
                        "name": name,
                        "arguments": _shrink(args),
                    },
                ),
            )

        def on_tool_complete(call_id, name, args, result) -> None:
            conn.emit_threadsafe(
                loop,
                event(
                    "session.tool_result",
                    {
                        "session_id": session.id,
                        "id": str(call_id),
                        "name": name,
                        "result": _shrink(result, limit=4000),
                    },
                ),
            )

        agent = session.agent
        agent.stream_delta_callback = on_delta if stream else None
        agent.tool_start_callback = on_tool_start
        agent.tool_complete_callback = on_tool_complete

        def _run() -> Dict[str, Any]:
            import threading

            session.thread_id = threading.get_ident()
            # ``AIAgent.chat()`` is ``run_conversation()[\"final_response\"]`` and
            # raises KeyError on every failure path, because failed turns return
            # {\"error\": ..., \"failed\": True} with no \"final_response\" key.
            # Call run_conversation directly so a provider error reaches the
            # desktop app as the provider's own message.
            return agent.run_conversation(message) or {}

        try:
            outcome = await asyncio.to_thread(_run)
        except Exception as exc:
            session.busy = False
            payload = {
                "session_id": session.id,
                "error": f"{type(exc).__name__}: {exc}",
            }
            await conn.send_frame(event("session.error", payload))
            raise BridgeError(AGENT_ERROR, payload["error"], {"session_id": session.id})
        finally:
            session.busy = False
            session.thread_id = None
            agent.stream_delta_callback = None
            agent.tool_start_callback = None
            agent.tool_complete_callback = None

        elapsed_ms = int((time.perf_counter() - started) * 1000)

        # A failed turn carries "error"/"failed" and no "final_response".
        if outcome.get("failed") or (outcome.get("error") and not outcome.get("final_response")):
            detail = {
                "session_id": session.id,
                "error": str(outcome.get("error") or "agent turn failed"),
                "partial": bool(outcome.get("partial")),
                "api_calls": outcome.get("api_calls"),
                "elapsed_ms": elapsed_ms,
                "tool_calls": tool_calls,
            }
            await conn.send_frame(event("session.error", detail))
            raise BridgeError(AGENT_ERROR, detail["error"], detail)

        session.turns += 1
        done = {
            "session_id": session.id,
            "text": outcome.get("final_response") or "",
            "elapsed_ms": elapsed_ms,
            "api_calls": outcome.get("api_calls"),
            "tool_calls": tool_calls,
            "model": session.model,
            "provider": session.provider,
        }
        await conn.send_frame(event("session.done", done))
        return done

    def _m_session_cancel(self, conn, params):
        sid = str(params.get("session_id") or "")
        session = self.sessions.get(sid)
        if session is None:
            raise BridgeError(SESSION_NOT_FOUND, f"no such session: {sid}")
        if not session.busy:
            return {"cancelled": False, "reason": "session is idle"}
        try:
            from tools.interrupt import set_interrupt

            set_interrupt(True, session.thread_id)
        except Exception as exc:
            raise BridgeError(CANCELLED, f"cancel failed: {exc}")
        return {"cancelled": True, "session_id": sid}

    # ── config.* ────────────────────────────────────────────────────────

    def _m_config_get(self, conn, params):
        from fetih_cli.config import cfg_get, get_config_path, get_env_path, load_config

        cfg = load_config()
        key = params.get("key")
        if key:
            value = cfg_get(cfg, *str(key).split("."))
            return {
                "key": key,
                "value": _redact(value, str(key).split(".")[-1]),
                "path": str(get_config_path()),
            }
        return {
            "config": _redact(cfg),
            "path": str(get_config_path()),
            "env_path": str(get_env_path()),
        }

    def _m_config_set(self, conn, params):
        key = params.get("key")
        if not isinstance(key, str) or not key:
            raise BridgeError(INVALID_PARAMS, "'key' is required (dotted path)")
        if "value" not in params:
            raise BridgeError(INVALID_PARAMS, "'value' is required")
        # Credential-shaped keys never travel through config.set. A *boolean*
        # is the one shape a credential can never take, so switches whose name
        # merely contains a hint word — ``security.redact_secrets`` is the
        # canonical example — stay editable. Without this carve-out that
        # security switch was permanently stuck at its current value in both
        # the desktop settings pages and the raw config editor.
        if _looks_secret(key.split(".")[-1]) and not isinstance(params["value"], bool):
            raise BridgeError(
                CONFIG_ERROR,
                "credentials are not written through config.set — "
                "they belong in the .env store",
            )

        from fetih_cli.config import _set_nested, is_managed, load_config, save_config

        if is_managed():
            raise BridgeError(
                CONFIG_ERROR, "this FETİH installation is managed and cannot be modified"
            )

        cfg = load_config()
        try:
            _set_nested(cfg, key, params["value"])
            save_config(cfg)
        except Exception as exc:
            raise BridgeError(CONFIG_ERROR, f"{type(exc).__name__}: {exc}")
        return {"key": key, "value": _redact(params["value"], key.split(".")[-1]), "saved": True}

    # ── providers.* ─────────────────────────────────────────────────────

    def _m_providers_list(self, conn, params):
        from fetih_cli.config import load_config, load_env
        from fetih_cli.providers import get_label, normalize_provider

        cfg = load_config()
        env = load_env()
        model_cfg = cfg.get("model") or {}
        if isinstance(model_cfg, str):
            active_provider, active_model = "", model_cfg
        else:
            active_provider = str(model_cfg.get("provider") or "")
            active_model = str(model_cfg.get("default") or model_cfg.get("model") or "")

        out: List[Dict[str, Any]] = []
        for pid, block in (cfg.get("providers") or {}).items():
            block = block if isinstance(block, dict) else {}
            key_env = str(block.get("key_env") or "")
            out.append(
                {
                    "id": pid,
                    "name": block.get("name") or _safe(get_label, pid, default=pid),
                    "base_url": block.get("base_url", ""),
                    "api_mode": block.get("api_mode", ""),
                    "default_model": block.get("default_model", ""),
                    "context_length": block.get("context_length"),
                    "discover_models": bool(block.get("discover_models")),
                    "key_env": key_env,
                    # Presence only — the value never leaves the process.
                    "key_present": bool(key_env and (env.get(key_env) or os.getenv(key_env))),
                    "source": "user-config",
                    "active": normalize_provider(pid) == normalize_provider(active_provider)
                    if active_provider
                    else False,
                }
            )

        return {
            "active": {"provider": active_provider, "model": active_model},
            "providers": out,
            "fallback_providers": cfg.get("fallback_providers") or [],
        }

    # ── skills.* ────────────────────────────────────────────────────────

    def _m_skills_list(self, conn, params):
        category = params.get("category")
        search = (params.get("search") or "").strip().lower()
        limit = int(params.get("limit") or 100)
        offset = int(params.get("offset") or 0)

        skills = _collect_skills()

        if category:
            skills = [s for s in skills if (s.get("category") or "") == category]
        if search:
            skills = [
                s
                for s in skills
                if search in (s.get("name") or "").lower()
                or search in (s.get("description") or "").lower()
            ]

        categories: Dict[str, int] = {}
        for s in _collect_skills():
            categories[s.get("category") or ""] = categories.get(s.get("category") or "", 0) + 1

        return {
            "total": len(skills),
            "offset": offset,
            "limit": limit,
            "categories": dict(sorted(categories.items(), key=lambda kv: -kv[1])),
            "skills": skills[offset : offset + limit],
        }

    # ── shell.* (Windows: Git Bash / WSL kabuk seçimi) ──────────────────

    def _m_shell_status(self, conn, params):
        """Windows kabuk backend'inin durumunu döndür.

        Ayarlar UI'ı bu bilgiyle Git Bash / WSL seçicisini, kurulu WSL
        dağıtımlarını ve seçili dağıtımdaki ``fetih`` kullanıcısının var olup
        olmadığını gösterir.  Windows dışında ``available: False`` döner.
        """
        try:
            from tools.environments import windows_shell as ws
        except Exception as exc:  # pragma: no cover - defensive
            return {"platform": platform.system(), "available": False,
                    "detail": f"kabuk modülü yüklenemedi: {exc}"}

        if platform.system() != "Windows":
            return {
                "platform": platform.system(),
                "available": False,
                "detail": "Kabuk seçimi yalnızca Windows'ta geçerlidir.",
            }

        pref = ws.read_shell_preference()
        wsl = ws.wsl_status()
        selected_distro = pref.get("distro") or wsl.get("default") or ""
        user = pref.get("user") or ""
        user_exists = None
        if wsl.get("available") and user:
            try:
                user_exists = ws.wsl_user_exists(selected_distro or None, user)
            except Exception:
                user_exists = None

        return {
            "platform": "Windows",
            "available": True,
            "selected": pref.get("shell") or ws.SHELL_GIT_BASH,
            "effective": ws.effective_shell(),
            "valid_shells": list(ws.VALID_SHELLS),
            "git_bash_path": ws.find_git_bash() or "",
            "wsl": {
                "available": bool(wsl.get("available")),
                "distros": wsl.get("distros") or [],
                "default": wsl.get("default") or "",
                "detail": wsl.get("detail") or "",
            },
            "selected_distro": selected_distro,
            "wsl_user": user,
            "wsl_user_exists": user_exists,
            "default_wsl_user": ws.DEFAULT_WSL_USER,
        }

    def _m_shell_ensure_user(self, conn, params):
        """WSL dağıtımında ayrılmış FETİH kullanıcısını (yoksa) oluştur."""
        if platform.system() != "Windows":
            raise BridgeError(INVALID_PARAMS, "shell.ensure_user yalnızca Windows'ta çalışır")
        try:
            from tools.environments import windows_shell as ws
        except Exception as exc:  # pragma: no cover - defensive
            raise BridgeError(CONFIG_ERROR, f"kabuk modülü yüklenemedi: {exc}")

        distro = (params.get("distro") or "").strip() or None
        user = (params.get("user") or ws.DEFAULT_WSL_USER).strip() or ws.DEFAULT_WSL_USER
        result = ws.ensure_wsl_user(distro=distro, user=user)
        if not result.get("ok"):
            raise BridgeError(CONFIG_ERROR, result.get("detail") or "kullanıcı oluşturulamadı")
        return result

    # ── system.* (tehlikeli bölge) ──────────────────────────────────────
    #
    # İki AYRI yıkıcı işlem; ikisi de FETİH'in kendi kodunu (fetih_cli.
    # uninstall) çağırır — masaüstü uygulaması dosya sistemine hiç dokunmaz.
    #
    #   system.reset_configuration → SADECE config.yaml + .env silinir; sohbet
    #                                geçmişi, hafıza ve günlükler KORUNUR.
    #   system.wipe_all_data       → FETIH_HOME altındaki HER ŞEY silinir.
    #
    # Her ikisi de ``confirm: true`` ister: bir yazım hatası ya da eski bir
    # istemci kazayla veri silemesin.

    def _require_confirm(self, params: Dict[str, Any], method: str) -> None:
        if params.get("confirm") is not True:
            raise BridgeError(
                INVALID_PARAMS,
                f"{method} requires 'confirm': true — refusing to delete anything",
            )
        from fetih_cli.config import is_managed

        if is_managed():
            raise BridgeError(
                CONFIG_ERROR,
                "this FETİH installation is managed and cannot be modified",
            )

    def _m_system_reset_configuration(self, conn, params):
        self._require_confirm(params, "system.reset_configuration")
        from fetih_cli.uninstall import WipeRefused, reset_configuration

        try:
            result = reset_configuration()
        except WipeRefused as exc:
            raise BridgeError(CONFIG_ERROR, str(exc))
        except Exception as exc:
            raise BridgeError(INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

        # Bir sonraki turun diskten silinmiş ayarları yeniden okumaması için
        # yapılandırma önbelleğini boşalt.
        _invalidate_config_cache()
        return result

    def _m_system_wipe_all_data(self, conn, params):
        self._require_confirm(params, "system.wipe_all_data")
        from fetih_cli.uninstall import WipeRefused, wipe_all_data

        # Açık oturumlar silinmiş bir hafıza/oturum deposuna yazmaya devam
        # etmesin: hepsi kapatılır.
        self.sessions.clear()

        try:
            result = wipe_all_data()
        except WipeRefused as exc:
            raise BridgeError(CONFIG_ERROR, str(exc))
        except Exception as exc:
            raise BridgeError(INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

        _invalidate_config_cache()
        result["restart_required"] = True
        return result

    # ── diagnostics.* ───────────────────────────────────────────────────

    def _m_diagnostics_info(self, conn, params):
        from fetih_cli.config import (
            detect_install_method,
            get_config_path,
            get_env_path,
            is_managed,
        )

        cfg_path = get_config_path()
        info: Dict[str, Any] = {
            "fetih_version": _fetih_version(),
            "protocol_version": PROTOCOL_VERSION,
            "python": {
                "version": sys.version.split()[0],
                "executable": sys.executable,
                "implementation": platform.python_implementation(),
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "node_arch": platform.architecture()[0],
            },
            "paths": {
                "config": str(cfg_path),
                "config_exists": cfg_path.exists(),
                "env": str(get_env_path()),
                "fetih_home": str(Path(cfg_path).parent),
                "repo_root": str(Path(__file__).resolve().parent.parent),
                "cwd": os.getcwd(),
            },
            "install": {
                "method": _safe(detect_install_method, default="unknown"),
                "managed": bool(_safe(is_managed, default=False)),
            },
            "bridge": {
                "uptime_s": round(time.time() - self._started, 3),
                "transport": conn.kind,
                "auth_required": bool(self.require_auth and self.token),
                "connections": len(self._conn_objs),
                "sessions": len(self.sessions),
                "pid": os.getpid(),
            },
        }

        try:
            from fetih_cli.config import load_config

            cfg = load_config()
            model_cfg = cfg.get("model") or {}
            if isinstance(model_cfg, dict):
                info["active_model"] = {
                    "provider": model_cfg.get("provider", ""),
                    "model": model_cfg.get("default") or model_cfg.get("model") or "",
                }
            info["toolsets"] = cfg.get("toolsets") or []
        except Exception as exc:
            info["config_error"] = f"{type(exc).__name__}: {exc}"

        return info

    # ── agent construction ──────────────────────────────────────────────

    def _build_session(
        self,
        *,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        toolsets: Optional[Any] = None,
        cwd: Optional[str] = None,
        skip_context_files: bool = False,
        skip_memory: bool = False,
    ) -> BridgeSession:
        """Build a real ``AIAgent``, mirroring ``fetih_cli/oneshot.py``.

        Kept deliberately close to the oneshot path so the bridge inherits the
        same provider resolution, toolset selection and session-store wiring
        the CLI already has — no second, divergent bootstrap.
        """
        from fetih_cli.config import load_config
        from fetih_cli.runtime_provider import resolve_runtime_provider
        from fetih_cli.tools_config import _get_platform_tools
        from run_agent import AIAgent

        cfg = load_config()
        model_cfg = cfg.get("model") or {}
        if isinstance(model_cfg, str):
            cfg_model, cfg_provider = model_cfg, ""
        else:
            cfg_model = model_cfg.get("default") or model_cfg.get("model") or ""
            cfg_provider = str(model_cfg.get("provider") or "")

        effective_model = (model or "").strip() or cfg_model
        effective_provider = (provider or "").strip() or cfg_provider or None

        try:
            runtime = resolve_runtime_provider(
                requested=effective_provider,
                target_model=effective_model or None,
            )
        except Exception as exc:
            raise BridgeError(
                CONFIG_ERROR, f"provider resolution failed: {type(exc).__name__}: {exc}"
            )

        toolsets_list: Optional[List[str]] = None
        if toolsets:
            if isinstance(toolsets, str):
                toolsets_list = [t.strip() for t in toolsets.split(",") if t.strip()]
            else:
                toolsets_list = [str(t).strip() for t in toolsets if str(t).strip()]
        else:
            try:
                toolsets_list = sorted(_get_platform_tools(cfg, "cli"))
            except Exception:
                toolsets_list = None

        session_db = None
        try:
            from fetih_state import SessionDB

            session_db = SessionDB()
        except Exception:
            session_db = None

        work_dir = str(cwd) if cwd else os.getcwd()

        try:
            agent = AIAgent(
                api_key=runtime.get("api_key"),
                base_url=runtime.get("base_url"),
                provider=runtime.get("provider"),
                api_mode=runtime.get("api_mode"),
                model=effective_model,
                enabled_toolsets=toolsets_list,
                quiet_mode=True,
                platform="cli",
                session_db=session_db,
                credential_pool=runtime.get("credential_pool"),
                clarify_callback=_bridge_clarify_callback,
                # Small-context endpoints (Groq's 8K-TPM free tier, GitHub
                # Models, most local servers) cannot carry FETİH's full
                # AGENTS.md + memory preamble on top of the tool schemas.
                # The desktop app can trade context for headroom per session.
                skip_context_files=bool(skip_context_files),
                skip_memory=bool(skip_memory),
            )
        except Exception as exc:
            raise BridgeError(
                AGENT_ERROR, f"agent construction failed: {type(exc).__name__}: {exc}"
            )

        agent.suppress_status_output = True
        agent.tool_gen_callback = None

        return BridgeSession(
            uuid.uuid4().hex[:12],
            agent,
            model=effective_model,
            provider=str(runtime.get("provider") or effective_provider or ""),
            cwd=work_dir,
        )


# --- helpers ----------------------------------------------------------------


def _session_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """The session-shaping fields ``session.new`` and ``session.send`` share."""
    return {
        "model": params.get("model"),
        "provider": params.get("provider"),
        "toolsets": params.get("toolsets"),
        "cwd": params.get("cwd"),
        "skip_context_files": bool(params.get("skip_context_files", False)),
        "skip_memory": bool(params.get("skip_memory", False)),
    }


def _bridge_clarify_callback(question: str, choices=None) -> str:
    """The desktop client has no synchronous clarify channel yet — keep the
    turn moving instead of stalling on a prompt nobody can answer."""
    if choices:
        return (
            f"[desktop bridge: no interactive prompt available. Choose the best "
            f"option from {choices} yourself and continue.]"
        )
    return (
        "[desktop bridge: no interactive prompt available. Make the most "
        "reasonable assumption and continue.]"
    )


def _invalidate_config_cache() -> None:
    """Drop FETİH's in-process config/env caches.

    ``load_config()`` memoises on (mtime, size), and ``load_env()`` keeps its
    own cache; after a wipe or reset both would otherwise keep serving values
    that no longer exist on disk.
    """
    try:
        from fetih_cli import config as _config

        _config._LOAD_CONFIG_CACHE.clear()
        _config._RAW_CONFIG_CACHE.clear()
    except Exception:
        pass
    try:
        from fetih_cli.config import invalidate_env_cache

        invalidate_env_cache()
    except Exception:
        pass


def _shrink(value: Any, limit: int = 2000) -> Any:
    """Cap oversized tool payloads so one 45 KB write_file doesn't flood the UI."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"… (+{len(value) - limit} chars)"
    if isinstance(value, dict):
        return {k: _shrink(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_shrink(v, limit) for v in value[:50]]
    return value


def _safe(fn: Callable[..., Any], *args, default: Any = None) -> Any:
    try:
        return fn(*args)
    except Exception:
        return default


def _fetih_version() -> str:
    try:
        from importlib.metadata import version

        return version("fetih")
    except Exception:
        pass
    try:
        import fetih_constants

        return str(getattr(fetih_constants, "VERSION", "") or "unknown")
    except Exception:
        return "unknown"


def _collect_skills() -> List[Dict[str, Any]]:
    """Installed skills first, then the skills bundled with this checkout."""
    out: List[Dict[str, Any]] = []
    seen: set = set()

    try:
        from tools.skills_tool import _find_all_skills

        for s in _find_all_skills(skip_disabled=True):
            name = s.get("name")
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(
                {
                    "name": name,
                    "description": s.get("description") or "",
                    "category": s.get("category") or "",
                    "source": "installed",
                }
            )
    except Exception:
        pass

    repo_root = Path(__file__).resolve().parent.parent
    for base, source in ((repo_root / "skills", "bundled"), (repo_root / "optional-skills", "optional")):
        if not base.is_dir():
            continue
        for skill_md in base.rglob("SKILL.md"):
            try:
                rel = skill_md.relative_to(base)
                category = rel.parts[0] if len(rel.parts) > 1 else ""
                head = skill_md.read_text(encoding="utf-8", errors="replace")[:3000]
                name, description = _parse_skill_head(head, skill_md.parent.name)
                if name in seen:
                    continue
                seen.add(name)
                out.append(
                    {
                        "name": name,
                        "description": description,
                        "category": category,
                        "source": source,
                    }
                )
            except Exception:
                continue

    out.sort(key=lambda s: (s.get("category") or "", s.get("name") or ""))
    return out


def _parse_skill_head(content: str, fallback_name: str) -> tuple:
    """Minimal YAML-frontmatter read — name + description only."""
    name, description = fallback_name, ""
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            try:
                import yaml

                fm = yaml.safe_load(parts[1]) or {}
                if isinstance(fm, dict):
                    name = str(fm.get("name") or fallback_name)
                    description = str(fm.get("description") or "")
            except Exception:
                pass
    if not description:
        body = content.split("---", 2)[-1]
        for line in body.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                description = line
                break
    return name, description[:300]


__all__ = ["BridgeServer", "BridgeSession"]

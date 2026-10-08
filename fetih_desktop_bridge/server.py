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
import json
import os
import platform
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import PROTOCOL_VERSION, agy_backend
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

#: Providers whose OAuth/subscription login completes WITHOUT stdin — a browser
#: loopback callback, a device-code poll, or reusing a local CLI session — so
#: the bridge can run the real ``fetih auth add`` path in a daemon thread.
#: Anthropic is excluded on purpose: its OAuth client is pinned to the
#: ``console.anthropic.com`` callback, so the user must copy a code. That flow
#: is driven by ``auth.begin`` / ``auth.complete`` with an in-app paste box.
_BRIDGE_BACKGROUND_AUTH = {
    "xai-oauth",
    "openai-codex",
    "google-gemini-cli",
    "qwen-oauth",
    "minimax-oauth",
}

#: Providers the desktop bridge serves itself rather than through the CLI's
#: provider resolver. They may appear in providers.catalog even though
#: ``fetih_cli.auth.resolve_provider`` rejects them (it explains why instead).
DESKTOP_ONLY_PROVIDERS = frozenset({agy_backend.PROVIDER_ID})

#: Advisory flow hint per provider so the desktop app can pick its login UI.
_AUTH_FLOW_KIND = {
    "anthropic": "paste_code",
    "xai-oauth": "loopback",
    "openai-codex": "device_code",
    "google-gemini-cli": "loopback",
    "qwen-oauth": "cli_session",
    "minimax-oauth": "loopback",
}


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


#: Ciddiyet sıralaması (rapor + liste için).
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_TR = {
    "critical": "Kritik", "high": "Yüksek", "medium": "Orta",
    "low": "Düşük", "info": "Bilgi",
}


def _build_findings_report(findings: List[Dict[str, Any]], fmt: str = "md") -> str:
    """Bulguları Markdown ya da HTML rapora dönüştürür. Saf/IO'suz → test edilebilir."""
    import html as _html

    fmt = "html" if str(fmt).lower() == "html" else "md"
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        buckets.setdefault(sev, []).append(f)
    ordered = [s for s in _SEVERITY_ORDER if s in buckets]
    ordered += [s for s in buckets if s not in _SEVERITY_ORDER]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    def _sev_label(s: str) -> str:
        return _SEVERITY_TR.get(s, s.capitalize())

    if fmt == "md":
        out = [f"# FETİH Güvenlik Raporu", "",
               f"Oluşturulma: {ts} · Toplam bulgu: {len(findings)}", ""]
        if not findings:
            out.append("_Henüz bulgu yok._")
        for sev in ordered:
            out.append(f"## {_sev_label(sev)} ({len(buckets[sev])})")
            out.append("")
            for f in buckets[sev]:
                out.append(f"### {f.get('title') or '(başlıksız)'}")
                if f.get("target"):
                    out.append(f"- **Hedef:** {f['target']}")
                if f.get("evidence"):
                    out.append(f"- **Kanıt:** {f['evidence']}")
                if f.get("recommendation"):
                    out.append(f"- **Öneri:** {f['recommendation']}")
                if f.get("reference"):
                    out.append(f"- **Referans:** {f['reference']}")
                if f.get("discovered_at"):
                    out.append(f"- **Zaman:** {f['discovered_at']}")
                out.append("")
        return "\n".join(out).rstrip() + "\n"

    # HTML
    def esc(v: Any) -> str:
        return _html.escape(str(v or ""))

    rows = []
    for sev in ordered:
        rows.append(f"<h2>{esc(_sev_label(sev))} ({len(buckets[sev])})</h2>")
        for f in buckets[sev]:
            rows.append(f"<div class='f sev-{esc(sev)}'><h3>{esc(f.get('title') or '(başlıksız)')}</h3><ul>")
            for key, lbl in (("target", "Hedef"), ("evidence", "Kanıt"),
                             ("recommendation", "Öneri"), ("reference", "Referans"),
                             ("discovered_at", "Zaman")):
                if f.get(key):
                    rows.append(f"<li><b>{lbl}:</b> {esc(f[key])}</li>")
            rows.append("</ul></div>")
    body = "\n".join(rows) if findings else "<p><em>Henüz bulgu yok.</em></p>"
    return (
        "<!doctype html><html lang='tr'><head><meta charset='utf-8'>"
        "<title>FETİH Güvenlik Raporu</title><style>"
        "body{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}"
        "h1{border-bottom:2px solid #444}.f{border-left:4px solid #888;padding:.2rem 1rem;margin:.6rem 0}"
        ".sev-critical{border-color:#d13438}.sev-high{border-color:#f7630c}"
        ".sev-medium{border-color:#ffb900}.sev-low{border-color:#0078d4}.sev-info{border-color:#888}"
        "ul{margin:.3rem 0}</style></head><body>"
        f"<h1>FETİH Güvenlik Raporu</h1><p>Oluşturulma: {esc(ts)} · Toplam bulgu: {len(findings)}</p>"
        f"{body}</body></html>"
    )


class BridgeSession:
    """One conversation, backed by a live ``AIAgent`` instance."""

    def __init__(
        self,
        session_id: str,
        agent,
        *,
        model: str,
        provider: str,
        cwd: str,
        history: Optional[List[Dict[str, Any]]] = None,
    ):
        self.id = session_id
        self.agent = agent
        self.model = model
        self.provider = provider
        self.cwd = cwd
        self.created_at = time.time()
        self.busy = False
        self.turns = 0
        self.thread_id: Optional[int] = None
        self.history: List[Dict[str, Any]] = list(history) if history else []
        # A model switch requested while a turn was running (session.set_model);
        # applied at the start of the next send so an agent is never swapped
        # mid-turn (prompt-cache rule). None when there is nothing pending.
        self.pending_model: Optional[str] = None
        self.pending_provider: Optional[str] = None

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


class FakeModelAgent:
    """Deterministic simulation agent for UI manual testing and screenshots.

    Executes the exact sequence:
    uzun düşünce → metin → araç → metin → düşünce → araç → metin
    """

    def __init__(self):
        self.stream_delta_callback = None
        self.reasoning_callback = None
        self.thinking_callback = None
        self.tool_start_callback = None
        self.tool_complete_callback = None

    def run_conversation(self, message: str, conversation_history: Any = None) -> Dict[str, Any]:
        import time

        # 1. Uzun Düşünce (15+ karakter, cümle içeren, Claude tarzı kilitlenecek özet)
        thought1 = (
            "Hedef sistem mimarisi ve yapılandırma dosyaları inceleniyor. "
            "Gereksinimler doğrultusunda index.html şablonu ve dizin yapısı hazırlanacak."
        )
        for chunk in thought1.split(" "):
            if self.reasoning_callback:
                self.reasoning_callback(chunk + " ")
            time.sleep(0.04)

        time.sleep(0.12)

        # 2. Metin
        text1 = "Masaüstünde hedef dizini oluşturup dosyayı hazırlamaya başlıyorum.\n"
        for ch in text1:
            if self.stream_delta_callback:
                self.stream_delta_callback(ch)
            time.sleep(0.01)

        time.sleep(0.12)

        # 3. Araç 1 (terminal)
        call_id1 = "call_fake_001"
        args1 = '{"command": "mkdir -p desktop_test"}'
        if self.tool_start_callback:
            self.tool_start_callback(call_id1, "terminal", args1)
        time.sleep(0.4)
        if self.tool_complete_callback:
            self.tool_complete_callback(call_id1, "terminal", args1, '{"status": "success", "stdout": "desktop_test created."}')

        time.sleep(0.12)

        # 4. Metin
        text2 = "Dizin başarıyla oluşturuldu. Şimdi web sayfası içeriğini kodluyorum.\n"
        for ch in text2:
            if self.stream_delta_callback:
                self.stream_delta_callback(ch)
            time.sleep(0.01)

        time.sleep(0.12)

        # 5. İkinci Düşünce
        thought2 = (
            "Modern HTML5 ve CSS yapısı oluşturuluyor. "
            "Sayfa bileşenleri ve başlık etiketleri doğrulanıyor."
        )
        for chunk in thought2.split(" "):
            if self.reasoning_callback:
                self.reasoning_callback(chunk + " ")
            time.sleep(0.04)

        time.sleep(0.12)

        # 6. Araç 2 (write_file)
        call_id2 = "call_fake_002"
        args2 = '{"path": "desktop_test/index.html", "content": "<!DOCTYPE html><html><body><h1>FETİH</h1></body></html>"}'
        if self.tool_start_callback:
            self.tool_start_callback(call_id2, "write_file", args2)
        time.sleep(0.4)
        if self.tool_complete_callback:
            self.tool_complete_callback(call_id2, "write_file", args2, '{"status": "success", "bytes_written": 62}')

        time.sleep(0.12)

        # 7. Final Metin
        text3 = "Tüm işlemler tamamlandı! index.html dosyası başarıyla kaydedildi."
        for ch in text3:
            if self.stream_delta_callback:
                self.stream_delta_callback(ch)
            time.sleep(0.01)

        return {"final_response": text1 + text2 + text3}


class BridgeServer:
    """Transport-agnostic JSON-RPC dispatcher."""

    def __init__(self, *, token: str = "", require_auth: bool = True, fake_model: bool = False):
        self.token = token
        self.require_auth = require_auth
        self.fake_model = fake_model or bool(os.getenv("FETIH_FAKE_MODEL"))
        self.sessions: Dict[str, BridgeSession] = {}
        self._connections: Dict[int, asyncio.AbstractEventLoop] = {}
        self._conn_objs: List[Any] = []
        self._methods: Dict[str, Callable[..., Any]] = {}
        self._started = time.time()
        # Pending Anthropic paste flows: flow_token -> {provider, code_verifier,
        # state, ts}. PKCE material stays server-side between auth.begin and
        # auth.complete and is never sent to the client.
        self._auth_pending: Dict[str, Dict[str, Any]] = {}
        # redirect_stdout (used to stream login console output) is process
        # global, so only one in-bridge login may capture stdout at a time.
        self._auth_lock = threading.Lock()

        from fetih_constants import get_fetih_home
        from fetih_desktop_bridge.findings_store import FindingsStore
        from fetih_desktop_bridge.session_store import SessionStore
        db_path = os.path.join(get_fetih_home(), "desktop_sessions.db")
        self.store = SessionStore(db_path)
        # Bulgular kalıcı (issue #33): uygulama kapanınca kaybolmaz; oturum
        # silinse de silinmez (ayrı veritabanı).
        self.findings = FindingsStore(os.path.join(get_fetih_home(), "desktop_findings.db"))

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
                "session.create": self._m_session_create,
                "session.list": self._m_session_list,
                "session.load": self._m_session_load,
                "session.rename": self._m_session_rename,
                "session.delete": self._m_session_delete,
                "session.delete_all": self._m_session_delete_all,
                "session.close": self._m_session_close,
                "session.send": self._m_session_send,
                "session.cancel": self._m_session_cancel,
                "session.approve": self._m_session_approve,
                "session.set_model": self._m_session_set_model,
                "config.get": self._m_config_get,
                "config.set": self._m_config_set,
                "config.schema": self._m_config_schema,
                "providers.list": self._m_providers_list,
                "providers.catalog": self._m_providers_catalog,
                "providers.models": self._m_providers_models,
                "providers.probe_local": self._m_providers_probe_local,
                "providers.auth_status": self._m_providers_auth_status,
                "auth.providers": self._m_auth_providers,
                "auth.begin": self._m_auth_begin,
                "auth.complete": self._m_auth_complete,
                "auth.login": self._m_auth_login,
                "auth.logout": self._m_auth_logout,
                "skills.list": self._m_skills_list,
                "file.tree": self._m_file_tree,
                "file.read": self._m_file_read,
                "file.diff": self._m_file_diff,
                "findings.list": self._m_findings_list,
                "findings.scan": self._m_findings_scan,
                "findings.export": self._m_findings_export,
                "findings.delete": self._m_findings_delete,
                "findings.clear": self._m_findings_clear,
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
                "session.thought",
                "session.status",
                "session.tool_call",
                "session.tool_result",
                "session.done",
                "session.error",
                "session.updated",
                "session.approval_request",
                "session.approval_resolved",
                "thought.label",
                "session.thought_label",
                "findings.discovered",
            ],
        }

    # ── session.* ───────────────────────────────────────────────────────

    def _m_session_new(self, conn, params):
        session = self._build_session(**_session_params(params))
        self.sessions[session.id] = session
        title = str(params.get("title") or "")
        self.store.create(sid=session.id, title=title)
        return session.snapshot()

    def _m_session_create(self, conn, params):
        sid = params.get("session_id")
        title = str(params.get("title") or "")
        sid = self.store.create(sid=sid, title=title)
        return {"session_id": sid, "title": title}

    def _m_session_list(self, conn, params):
        return {"sessions": self.store.list()}

    def _m_session_load(self, conn, params):
        sid = str(params.get("session_id") or "")
        if not sid:
            raise BridgeError(INVALID_PARAMS, "missing 'session_id'")
        items = self.store.items(sid)
        title = self.store.title(sid)
        running = False
        pending = None
        session = self.sessions.get(sid)
        if session and session.busy and getattr(session, "recorder", None):
            running = True
            snap = session.recorder.snapshot()
            if snap:
                pending = snap
        return {
            "session_id": sid,
            "title": title,
            "items": items,
            "running": running,
            "pending": pending,
        }

    def _m_session_rename(self, conn, params):
        sid = str(params.get("session_id") or "")
        title = str(params.get("title") or "")
        if not sid:
            raise BridgeError(INVALID_PARAMS, "missing 'session_id'")
        self.store.rename(sid, title)
        loop = self.loop_for(conn) or asyncio.get_running_loop()
        conn.emit_threadsafe(
            loop,
            event("session.updated", {"session_id": sid, "title": title, "updated_at": time.time()}),
        )
        return {"session_id": sid, "title": title}

    def _m_session_delete(self, conn, params):
        sid = str(params.get("session_id") or "")
        if not sid:
            raise BridgeError(INVALID_PARAMS, "missing 'session_id'")
        self.store.delete(sid)
        self.sessions.pop(sid, None)
        return {"deleted": True, "session_id": sid}

    def _m_session_delete_all(self, conn, params):
        self.store.delete_all()
        self.sessions.clear()
        return {"deleted_all": True}

    def _m_session_close(self, conn, params):
        sid = str(params.get("session_id") or "")
        session = self.sessions.pop(sid, None)
        if session is None and not self.store.exists(sid):
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
                # If session exists in store, instantiate an in-memory session for it
                if self.store.exists(str(sid)):
                    p = _session_params(params)
                    p["session_id"] = str(sid)
                    session = self._build_session(**p)
                    self.sessions[session.id] = session
                else:
                    loop = self.loop_for(conn) or asyncio.get_running_loop()
                    conn.emit_threadsafe(
                        loop,
                        event("session.error", {"session_id": str(sid), "error": f"no such session: {sid}"}),
                    )
                    raise BridgeError(SESSION_NOT_FOUND, f"no such session: {sid}")
        else:
            session = self._build_session(**_session_params(params))
            self.sessions[session.id] = session

        if session.busy:
            raise BridgeError(SESSION_BUSY, f"session {session.id} is already running a turn")

        # Apply a model switch requested mid-turn (session.set_model while busy)
        # now, at the top of the next turn — never swapping an agent in flight.
        if session.pending_model or session.pending_provider:
            self._apply_model_switch(
                conn, session,
                session.pending_model or session.model,
                session.pending_provider or session.provider,
            )

        from fetih_desktop_bridge.session_store import TranscriptRecorder
        from fetih_desktop_bridge.thought_labeler import ThoughtLabeler

        recorder = TranscriptRecorder(self.store, session.id)
        session.recorder = recorder

        # Ensure session in store and initialize title from first message if empty
        if not self.store.exists(session.id) or not self.store.title(session.id):
            clean_title = message.strip().replace("\r\n", " ").replace("\n", " ")
            if len(clean_title) > 36:
                clean_title = clean_title[:35] + "…"
            self.store.create(sid=session.id, title=clean_title)

        recorder.text("user", message)
        recorder.flush()

        loop = self.loop_for(conn) or asyncio.get_running_loop()
        stream = params.get("stream", True) is not False

        # ── Approval wiring ──────────────────────────────────────────────
        # Dangerous commands block the agent thread inside tools.approval and
        # call this notify, which surfaces a ``session.approval_request`` the
        # desktop answers with ``session.approve`` → resolve_gateway_approval.
        # Keyed by session id so parallel turns don't cross wires.
        try:
            from tools import approval as _approval
        except Exception:
            _approval = None

        def _approval_notify(approval_data) -> None:
            data = approval_data if isinstance(approval_data, dict) else {}
            payload = {
                "session_id": session.id,
                "request_id": uuid.uuid4().hex[:12],
                "command": data.get("command") if data else str(approval_data),
                "description": data.get("description", ""),
                "pattern_key": data.get("pattern_key", ""),
                "pattern_keys": data.get("pattern_keys", []),
            }
            conn.emit_threadsafe(loop, event("session.approval_request", payload))

        if _approval is not None:
            try:
                _approval.register_gateway_notify(session.id, _approval_notify)
                _approval.load_permanent_allowlist()
            except Exception:
                _approval = None

        def on_thought_label(sid: str, label: str) -> None:
            recorder.set_thought_label(label)
            conn.emit_threadsafe(
                loop, event("thought.label", {"session_id": sid, "label": label})
            )
            conn.emit_threadsafe(
                loop, event("session.thought_label", {"session_id": sid, "label": label})
            )

        thought_labeler = ThoughtLabeler(
            session_id=session.id,
            loop=loop,
            on_label=on_thought_label,
            fake_model=self.fake_model,
        )

        session.busy = True
        started = time.perf_counter()
        tool_calls: List[Dict[str, Any]] = []

        # These callbacks fire on the worker thread; every emit is marshalled
        # back onto the event loop via Connection.emit_threadsafe.
        dsml_suppressed = False

        def on_delta(text: str) -> None:
            nonlocal dsml_suppressed
            if dsml_suppressed:
                return
            if "DSML" in text or "<tool_call" in text or "<function_call" in text:
                dsml_suppressed = True
                return
            if stream and text:
                thought_labeler.on_close()
                recorder.text("assistant", text)
                conn.emit_threadsafe(
                    loop, event("session.delta", {"session_id": session.id, "text": text})
                )

        def on_thought(text: str) -> None:
            # Genuine chain-of-thought from the model (DeepSeek reasoner, o1,
            # Groq thinking, ...). Streamed incrementally and appended by the
            # desktop app's Reasoning panel.
            if stream and text:
                thought_labeler.on_chunk(text)
                recorder.text("thought", text)
                conn.emit_threadsafe(
                    loop, event("session.thought", {"session_id": session.id, "text": text})
                )

        def on_status(text: str) -> None:
            # Decorative "still working" ticker (random kaomoji + verb) meant
            # for the CLI's terminal spinner — NOT model reasoning. Sent as a
            # separate event so the desktop app can show it as a transient
            # status label instead of piling it into the Reasoning transcript.
            # See agent/conversation_loop.py's thinking_callback call sites.
            if stream:
                conn.emit_threadsafe(
                    loop, event("session.status", {"session_id": session.id, "text": text or ""})
                )

        def on_tool_start(call_id, name, args) -> None:
            thought_labeler.on_close()
            recorder.tool_call(call_id, name, args)
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
            recorder.tool_result(call_id, result)
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
            # Scan tool outputs for security findings and captured CTF flags
            res_str = str(result)
            import re
            flag_match = re.search(r"(?:CTF|FLAG|fetih)\{[A-Za-z0-9_\-!@#$%^&*+=]+\}", res_str, re.IGNORECASE)
            if flag_match:
                flag = flag_match.group(0)
                finding_dict = {
                    "id": str(uuid.uuid4().hex[:8]),
                    "title": f"CTF Flag Yakalandı: {flag}",
                    "target": f"tool:{name}",
                    "severity": "Critical",
                    "evidence": flag,
                    "recommendation": "Ajan oturumunda yakalanan bayrak. Rapor ve bulgulara kaydedildi.",
                    "reference": "CTF-FLAG",
                    "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                self._record_finding(conn, loop, finding_dict, session.id)

        agent = session.agent
        agent.stream_delta_callback = on_delta if stream else None
        agent.reasoning_callback = on_thought if stream else None
        agent.thinking_callback = on_status if stream else None
        agent.tool_start_callback = on_tool_start
        agent.tool_complete_callback = on_tool_complete

        def _run() -> Dict[str, Any]:
            import threading

            session.thread_id = threading.get_ident()
            # Bind the approval session key on THIS worker thread so dangerous
            # commands the agent runs look up our notify callback (above) and
            # block here until the desktop responds.
            _key_token = None
            if _approval is not None:
                try:
                    _key_token = _approval.set_current_session_key(session.id)
                except Exception:
                    _key_token = None
            conv_hist = session.history if session.history else None
            try:
                if conv_hist:
                    res = agent.run_conversation(message, conversation_history=conv_hist) or {}
                else:
                    res = agent.run_conversation(message) or {}
            except TypeError:
                res = agent.run_conversation(message) or {}
            finally:
                if _approval is not None and _key_token is not None:
                    try:
                        _approval.reset_current_session_key(_key_token)
                    except Exception:
                        pass
            if getattr(agent, "_session_messages", None):
                session.history = list(agent._session_messages)
            return res

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
            if _approval is not None:
                # Releases any approval still blocking the agent thread so the
                # turn can unwind even if the user never answered.
                try:
                    _approval.unregister_gateway_notify(session.id)
                except Exception:
                    pass
            thought_labeler.on_close()
            session.busy = False
            session.thread_id = None
            session.recorder = None
            agent.stream_delta_callback = None
            agent.reasoning_callback = None
            agent.thinking_callback = None
            agent.tool_start_callback = None
            agent.tool_complete_callback = None
            recorder.flush()
            try:
                conn.emit_threadsafe(
                    loop,
                    event(
                        "session.updated",
                        {
                            "session_id": session.id,
                            "title": self.store.title(session.id),
                            "updated_at": time.time(),
                        },
                    ),
                )
            except Exception:
                pass

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
        # Oturum boyunca kümülatif token kullanımı (ajan sayaçlarından).
        _agent = session.agent
        tokens = {
            "total": int(getattr(_agent, "session_total_tokens", 0) or 0),
            "prompt": int(getattr(_agent, "session_prompt_tokens", 0) or 0),
            "completion": int(getattr(_agent, "session_completion_tokens", 0) or 0),
        }
        done = {
            "session_id": session.id,
            "text": outcome.get("final_response") or "",
            "thought": outcome.get("reasoning") or outcome.get("reasoning_text") or "",
            "elapsed_ms": elapsed_ms,
            "api_calls": outcome.get("api_calls"),
            "tool_calls": tool_calls,
            "tokens": tokens,
            "model": session.model,
            "provider": session.provider,
        }
        await conn.send_frame(event("session.done", done))

        # İlk tur bitince ham ilk-mesaj başlığının yerine kısa, anlamlı bir
        # başlık üret (ChatGPT tarzı). Arka planda — turu/yanıtı GECİKTİRMEZ.
        if session.turns == 1 and done["text"] and not self.fake_model:
            self._maybe_auto_title(conn, loop, session, message, done["text"])

        return done

    def _maybe_auto_title(self, conn, loop, session, user_msg: str, assistant_text: str) -> None:
        """İlk alışverişten kısa bir başlık türetip sessizce kaydeder ve UI'ya
        ``session.updated`` yayar. Ağ/model hatası başlığı ham haliyle bırakır."""
        import threading

        def _work() -> None:
            try:
                from agent.title_generator import generate_title

                # main_runtime=None → yardımcı (ucuz/hızlı) model kullanılır.
                title = generate_title(user_msg, assistant_text, main_runtime=None)
            except Exception:
                title = None
            if not title:
                return
            try:
                self.store.rename(session.id, title)
                conn.emit_threadsafe(
                    loop,
                    event(
                        "session.updated",
                        {
                            "session_id": session.id,
                            "title": title,
                            "updated_at": time.time(),
                        },
                    ),
                )
            except Exception:
                pass

        threading.Thread(target=_work, daemon=True).start()

    def _m_session_cancel(self, conn, params):
        sid = str(params.get("session_id") or "")
        session = self.sessions.get(sid)
        if session is None:
            raise BridgeError(SESSION_NOT_FOUND, f"no such session: {sid}")
        if not session.busy:
            return {"cancelled": False, "reason": "session is idle"}

        # Release any approval currently blocking the agent thread, otherwise
        # the interrupt can't be noticed until the user answers the prompt.
        try:
            from tools.approval import resolve_gateway_approval

            resolve_gateway_approval(sid, "deny", resolve_all=True)
        except Exception:
            pass

        # Prefer agent.interrupt(): it propagates to in-flight tool worker
        # threads too, not just the main agent thread (which is all that
        # set_interrupt(thread_id) reaches).
        interrupted = False
        try:
            agent = getattr(session, "agent", None)
            if agent is not None and hasattr(agent, "interrupt"):
                agent.interrupt()
                interrupted = True
        except Exception:
            interrupted = False

        try:
            from tools.interrupt import set_interrupt

            set_interrupt(True, session.thread_id)
        except Exception as exc:
            if not interrupted:
                raise BridgeError(CANCELLED, f"cancel failed: {exc}")
        return {"cancelled": True, "session_id": sid}

    def _m_session_approve(self, conn, params):
        """Resolve a pending dangerous-command approval for a session.

        ``choice`` is one of ``once`` (allow this single time), ``session``
        (allow this pattern for the rest of the session), ``always`` (persist
        to the permanent allowlist), or ``deny`` (block, do not retry).  When
        ``all`` is true every approval queued for the session is resolved with
        the same choice at once.
        """
        sid = str(params.get("session_id") or "")
        choice = str(params.get("choice") or "").lower()
        resolve_all = bool(params.get("all"))
        if choice not in {"once", "session", "always", "deny"}:
            raise BridgeError(INVALID_PARAMS, "choice must be once|session|always|deny")

        try:
            from tools.approval import resolve_gateway_approval

            resolved = resolve_gateway_approval(sid, choice, resolve_all=resolve_all)
        except Exception as exc:
            raise BridgeError(INTERNAL_ERROR, f"approval resolve failed: {exc}")

        # Echo an event so a card the desktop shows can be dismissed even when
        # the resolution came from elsewhere (e.g. a bulk approve).
        try:
            loop = self.loop_for(conn)
            if loop is not None:
                conn.emit_threadsafe(
                    loop,
                    event(
                        "session.approval_resolved",
                        {
                            "session_id": sid,
                            "choice": choice,
                            "resolved": resolved,
                            "all": resolve_all,
                        },
                    ),
                )
        except Exception:
            pass

        return {"resolved": resolved, "choice": choice, "session_id": sid}

    def _apply_model_switch(self, conn, session, model: str, provider: str) -> None:
        """Rebuild a session's agent for a new provider/model, preserving history.

        Must only be called when the session is NOT running a turn. Rebuilds
        from the stored transcript so the conversation continues under the new
        model, clears any pending switch, and emits ``session.model_changed``
        so the chat can draw a 'switched to <model>' divider.
        """
        rebuilt = self._build_session(
            session_id=session.id,
            model=(model or "").strip() or session.model,
            provider=(provider or "").strip() or session.provider,
        )
        session.agent = rebuilt.agent
        session.model = rebuilt.model
        session.provider = rebuilt.provider
        session.pending_model = None
        session.pending_provider = None

        loop = self.loop_for(conn) or asyncio.get_running_loop()
        conn.emit_threadsafe(
            loop,
            event(
                "session.model_changed",
                {
                    "session_id": session.id,
                    "provider": session.provider,
                    "model": session.model,
                },
            ),
        )

    def _m_session_set_model(self, conn, params):
        """Switch an existing session's provider/model (issue #55).

        Idle session → the agent is rebuilt now and the next turn uses the new
        model. Busy session → the switch is remembered and applied at the start
        of the next turn (an agent is never swapped mid-turn). Session-scoped:
        the global ``config.yaml`` default is left untouched.
        """
        sid = str(params.get("session_id") or "").strip()
        if not sid:
            raise BridgeError(INVALID_PARAMS, "'session_id' is required")
        provider = str(params.get("provider") or "").strip()
        model = str(params.get("model") or "").strip()
        if not provider and not model:
            raise BridgeError(INVALID_PARAMS, "provide 'provider' and/or 'model'")

        session = self.sessions.get(sid)
        if session is None:
            if not self.store.exists(sid):
                raise BridgeError(SESSION_NOT_FOUND, f"no such session: {sid}")
            # Materialize a live session so the override has somewhere to live.
            session = self._build_session(session_id=sid)
            self.sessions[sid] = session

        if session.busy:
            session.pending_model = model or session.model
            session.pending_provider = provider or session.provider
            return {
                "session_id": sid,
                "applied": "next_turn",
                "provider": session.pending_provider,
                "model": session.pending_model,
            }

        try:
            self._apply_model_switch(conn, session, model, provider)
        except BridgeError:
            raise
        except Exception as exc:
            raise BridgeError(
                AGENT_ERROR, f"model switch failed: {type(exc).__name__}: {exc}"
            )
        return {
            "session_id": sid,
            "applied": "now",
            "provider": session.provider,
            "model": session.model,
        }

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

    def _m_config_schema(self, conn, params):
        """Describe config.yaml leaves from DEFAULT_CONFIG: path, type, default.

        Lets the desktop editor render the right control for keys whose live
        value is null/empty (type can't be inferred from JSON null) and offer
        reset-to-default. Secret-shaped leaves are typed but their default is
        withheld — defaults never carry credential material.
        """
        from fetih_cli.config import DEFAULT_CONFIG

        def _type_of(v):
            if isinstance(v, bool):
                return "bool"
            if isinstance(v, int):
                return "int"
            if isinstance(v, float):
                return "float"
            if isinstance(v, list):
                return "list"
            if isinstance(v, dict):
                return "object"
            if v is None:
                return "null"
            return "string"

        fields: List[Dict[str, Any]] = []

        def _walk(prefix: str, obj: Any) -> None:
            if not isinstance(obj, dict):
                return
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(value, dict):
                    _walk(path, value)
                    continue
                leaf: Dict[str, Any] = {"path": path, "type": _type_of(value)}
                if _looks_secret(str(key)):
                    leaf["secret"] = True
                    leaf["default"] = None
                else:
                    leaf["default"] = value
                fields.append(leaf)

        _walk("", DEFAULT_CONFIG)
        return {"fields": fields, "version": DEFAULT_CONFIG.get("_config_version")}

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

    def _m_providers_catalog(self, conn, params):
        """Return the CANONICAL provider catalog straight out of the CLI.

        ``providers.list`` answers "what has the user configured?" — it walks
        ``config.yaml``'s ``providers:`` block and is empty on a fresh install.
        This method answers the different question the setup wizard actually
        needs: "which provider ids does this FETİH runtime accept?"

        The desktop shell used to answer that from a hand-maintained C# table.
        When an id in that table drifted from the CLI's own registry, setup
        completed happily and then the first chat turn died with
        ``Unknown provider '<id>'``. Serving the ids from the same
        ``auth.PROVIDER_REGISTRY`` that ``resolve_provider()`` consults makes
        that class of bug unrepresentable: if it is listed here, it resolves.
        """
        from fetih_cli import auth as _auth

        try:
            from providers import get_provider_profile, list_providers
        except Exception:  # pragma: no cover - providers pkg always ships
            get_provider_profile, list_providers = (lambda _n: None), (lambda: [])

        # Canonical ids only: PROVIDER_REGISTRY also holds alias -> same object
        # entries (groqcloud, groq-cloud …). Emit the canonical row once and
        # carry its aliases alongside it.
        alias_map: Dict[str, List[str]] = {}
        for pid, pconfig in _auth.PROVIDER_REGISTRY.items():
            if pid != pconfig.id:
                alias_map.setdefault(pconfig.id, []).append(pid)

        out: List[Dict[str, Any]] = []
        seen: set = set()
        for pid, pconfig in _auth.PROVIDER_REGISTRY.items():
            if pid != pconfig.id or pconfig.id in seen:
                continue
            seen.add(pconfig.id)
            profile = _safe(get_provider_profile, pconfig.id)
            base_url = pconfig.inference_base_url or getattr(profile, "base_url", "")
            out.append(
                {
                    "id": pconfig.id,
                    "name": pconfig.name,
                    "aliases": sorted(alias_map.get(pconfig.id, [])),
                    "auth_type": pconfig.auth_type,
                    "api_key_env_vars": list(pconfig.api_key_env_vars),
                    "base_url_env_var": pconfig.base_url_env_var,
                    "base_url": base_url,
                    "api_mode": getattr(profile, "api_mode", "") or "",
                    "display_name": getattr(profile, "display_name", "") or pconfig.name,
                    "signup_url": getattr(profile, "signup_url", "") or "",
                    "is_local": _is_local_endpoint(base_url),
                    "kind": _provider_kind(pconfig, base_url),
                }
            )

        # Profiles with no auth (pure local endpoints such as Ollama) never
        # reach PROVIDER_REGISTRY — it only auto-extends api_key providers —
        # but the wizard must still offer them.
        for profile in _safe(list_providers, default=[]) or []:
            if profile.name in seen:
                continue
            seen.add(profile.name)
            out.append(
                {
                    "id": profile.name,
                    "name": profile.display_name or profile.name,
                    "aliases": sorted(profile.aliases),
                    "auth_type": profile.auth_type,
                    "api_key_env_vars": list(profile.env_vars),
                    "base_url_env_var": "",
                    "base_url": profile.base_url,
                    "api_mode": profile.api_mode,
                    "display_name": profile.display_name or profile.name,
                    "signup_url": profile.signup_url,
                    "is_local": _is_local_endpoint(profile.base_url),
                    "kind": _provider_kind(None, profile.base_url, profile.auth_type),
                }
            )

        # Google Antigravity CLI: a desktop-only backend (see agy_backend),
        # offered only when Google's official `agy` binary is installed here.
        if agy_backend.PROVIDER_ID not in seen and _safe(agy_backend.find_agy):
            out.append(
                {
                    "id": agy_backend.PROVIDER_ID,
                    "name": "Google Antigravity CLI",
                    "aliases": ["agy", "antigravity"],
                    "auth_type": "external_process",
                    "api_key_env_vars": [],
                    "base_url_env_var": "",
                    "base_url": "",
                    "api_mode": "external_process",
                    "display_name": "Google Antigravity CLI (Pro aboneliği)",
                    "signup_url": "https://antigravity.google",
                    "is_local": False,
                    "kind": "cli_login",
                }
            )

        out.sort(key=lambda r: r["id"])
        return {"providers": out, "count": len(out)}

    def _m_providers_models(self, conn, params):
        """Model ids offered for one provider — live endpoint first.

        The wizard used to ship a hardcoded placeholder model. Providers
        retire model ids (Groq dropped ``llama-3.3-70b-versatile``), so a
        stale placeholder turns setup's "success" into a 404 on the first
        message. Asking the provider is the only answer that cannot go stale.
        """
        pid = str(params.get("provider") or "").strip()
        if not pid:
            raise BridgeError(INVALID_PARAMS, "'provider' is required")

        source = "fallback"
        models: List[str] = []

        # Anthropic: ask the account's OWN /v1/models endpoint when a token is
        # available (OAuth subscription or API key). The static CLI catalog
        # lags real releases — it was missing the whole Claude 5 family while
        # the live endpoint returns it. Falls back to the catalog on any error
        # or when not signed in.
        # Antigravity CLI: whatever the signed-in `agy` account offers.
        if pid == agy_backend.PROVIDER_ID:
            agy_models = _safe(agy_backend.list_models, default=None) or []
            return {
                "provider": pid,
                "models": agy_models,
                "source": "live" if agy_models else "fallback",
                "recommended": agy_models[0] if agy_models else "",
            }

        if pid == "anthropic":
            live_anthropic = _safe(_anthropic_live_model_ids, default=None)
            if live_anthropic:
                return {
                    "provider": pid,
                    "models": live_anthropic,
                    "source": "live",
                    "recommended": live_anthropic[0] if live_anthropic else "",
                }

        try:
            from providers import get_provider_profile

            profile = get_provider_profile(pid)
        except Exception:
            profile = None

        # The CLI's own picker first, so the desktop shell and ``fetih model``
        # never disagree about what exists.
        live = _safe(_provider_model_ids_for, pid, default=None)
        if live:
            models = [str(m) for m in live]
            source = "live"
        elif profile is not None and profile.fallback_models:
            models = [str(m) for m in profile.fallback_models]

        # Rank the curated tool-calling ids the profile vouches for ahead of
        # everything else. A live catalog also carries transcription, speech
        # and safety-classifier models; the agent loop cannot drive those, and
        # models[0] is what the wizard offers as the default.
        curated = [str(m) for m in (getattr(profile, "fallback_models", ()) or ())]
        if curated and models:
            preferred = [m for m in curated if m in models]
            models = preferred + [m for m in models if m not in preferred]

        return {
            "provider": pid,
            "models": models,
            "source": source,
            "recommended": models[0] if models else "",
        }

    def _m_providers_probe_local(self, conn, params):
        """Is a local inference server up, and what has it downloaded?

        Ollama and LM Studio need no API key — asking for one is the wrong
        question. What the wizard actually needs to know is whether the
        daemon is running and which models the user already pulled.
        """
        import json as _json
        import urllib.error
        import urllib.request

        pid = str(params.get("provider") or "ollama").strip()
        base = str(params.get("base_url") or "").strip().rstrip("/")

        if not base:
            base = {
                "ollama": "http://localhost:11434",
                "lmstudio": "http://127.0.0.1:1234/v1",
            }.get(pid, "")
        if not base:
            raise BridgeError(INVALID_PARAMS, f"no default endpoint known for '{pid}'")

        # Ollama's native tag listing carries sizes; every other local server
        # we support speaks the OpenAI-compatible /models shape.
        if pid == "ollama":
            probe_url = base[: -len("/v1")].rstrip("/") + "/api/tags" if base.endswith("/v1") else base + "/api/tags"
        else:
            probe_url = base + "/models" if base.endswith("/v1") else base + "/v1/models"

        try:
            req = urllib.request.Request(probe_url, headers={"User-Agent": "fetih-desktop-bridge"})
            with urllib.request.urlopen(req, timeout=float(params.get("timeout") or 4.0)) as resp:
                payload = _json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            # A 401/403 still proves something is listening on that port.
            return {
                "provider": pid,
                "running": True,
                "endpoint": probe_url,
                "models": [],
                "detail": f"HTTP {exc.code}",
            }
        except Exception as exc:
            return {
                "provider": pid,
                "running": False,
                "endpoint": probe_url,
                "models": [],
                "detail": f"{type(exc).__name__}: {exc}",
            }

        models: List[str] = []
        if isinstance(payload, dict):
            for item in payload.get("models") or payload.get("data") or []:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("model") or item.get("id")
                    if name:
                        models.append(str(name))
                elif item:
                    models.append(str(item))

        return {
            "provider": pid,
            "running": True,
            "endpoint": probe_url,
            "models": sorted(set(models)),
            "detail": "",
        }

    def _m_providers_auth_status(self, conn, params):
        """Is this provider signed in? Read-only, never prompts.

        The OAuth providers (Gemini Code Assist, Codex/ChatGPT, Qwen, xAI)
        cannot be authenticated by pasting a string into a text box — they
        need a browser round trip that the CLI already implements. The
        wizard's job is therefore to (a) launch that real flow and (b) poll
        this method until it reports success. Nothing here is simulated: the
        answer comes from the same ``auth.get_auth_status`` the CLI uses.

        Returns presence/expiry facts only — never a token.
        """
        pid = str(params.get("provider") or "").strip()
        if not pid:
            raise BridgeError(INVALID_PARAMS, "'provider' is required")

        # Desktop-only backend: "signed in" means the official `agy` can list
        # models under the user's own Antigravity login.
        if pid == agy_backend.PROVIDER_ID:
            return _safe(agy_backend.status, default=None) or {
                "provider": pid,
                "logged_in": False,
                "auth_type": "external_process",
            }

        from fetih_cli.auth import get_auth_status

        try:
            status = get_auth_status(pid) or {}
        except Exception as exc:
            return {
                "provider": pid,
                "logged_in": False,
                "detail": f"{type(exc).__name__}: {exc}",
                "auth_type": "",
            }

        # Whitelist the non-secret fields; get_auth_status shapes differ per
        # provider and some carry token material.
        safe_keys = (
            "logged_in", "expired", "expires_at", "email", "account",
            "plan", "source", "auth_type", "configured", "reason", "detail",
        )
        out: Dict[str, Any] = {"provider": pid}
        for key in safe_keys:
            if key in status and not _looks_secret(key):
                out[key] = status[key]
        out["logged_in"] = bool(status.get("logged_in") or status.get("configured"))
        return out

    # ── auth.* ──────────────────────────────────────────────────────────

    def _m_auth_providers(self, conn, params):
        """List OAuth/subscription-capable providers and each one's flow kind.

        Lets the desktop decide which login UI to show (an in-app paste box
        for Anthropic vs. a browser/device flow the bridge drives) without
        hardcoding the canonical set on the C# side. Read-only, no secrets.
        """
        try:
            from fetih_cli.auth_commands import _OAUTH_CAPABLE_PROVIDERS
            capable = sorted(_OAUTH_CAPABLE_PROVIDERS)
        except Exception:
            capable = sorted(_AUTH_FLOW_KIND)
        providers = [
            {
                "provider": pid,
                "flow": _AUTH_FLOW_KIND.get(pid, "background"),
                "in_process": pid == "anthropic" or pid in _BRIDGE_BACKGROUND_AUTH,
            }
            for pid in capable
        ]
        return {"providers": providers}

    def _m_auth_begin(self, conn, params):
        """Start the Anthropic (Claude Pro/Max) in-app paste login.

        Returns the authorize URL the app opens in a browser plus an opaque
        ``flow_token``. The user copies the code Anthropic shows and the app
        calls ``auth.complete``. The PKCE verifier and state stay server-side.
        """
        provider = str(params.get("provider") or "anthropic").strip()
        if provider != "anthropic":
            raise BridgeError(
                INVALID_PARAMS,
                "auth.begin drives the Anthropic paste flow only; "
                "use auth.login for browser/device providers",
            )
        from agent import anthropic_adapter
        info = anthropic_adapter.build_fetih_oauth_authorize_url()

        now = time.time()
        # Evict stale pending flows (older than 15 min) so the map can't grow.
        for stale in [t for t, v in self._auth_pending.items() if now - v.get("ts", now) > 900]:
            self._auth_pending.pop(stale, None)

        flow_token = uuid.uuid4().hex
        self._auth_pending[flow_token] = {
            "provider": provider,
            "code_verifier": info["code_verifier"],
            "state": info["state"],
            "ts": now,
        }
        return {
            "provider": provider,
            "flow": "paste_code",
            "authorize_url": info["authorize_url"],
            "flow_token": flow_token,
        }

    def _m_auth_complete(self, conn, params):
        """Finish the Anthropic paste flow: exchange the code and store tokens."""
        provider = str(params.get("provider") or "anthropic").strip()
        flow_token = str(params.get("flow_token") or "").strip()
        code = str(params.get("code") or "").strip()
        if not code:
            raise BridgeError(INVALID_PARAMS, "'code' is required")

        pending = self._auth_pending.pop(flow_token, None)
        if pending is None:
            raise BridgeError(
                INVALID_PARAMS,
                "unknown or expired 'flow_token' — start again with auth.begin",
            )

        from agent import anthropic_adapter
        creds = anthropic_adapter.exchange_fetih_oauth_code(
            code, pending["code_verifier"], pending.get("state", "")
        )
        if not creds:
            raise BridgeError(
                CONFIG_ERROR,
                "token exchange failed — the code may be wrong or expired",
            )
        try:
            from fetih_cli.auth_commands import persist_anthropic_oauth
            label = persist_anthropic_oauth(creds)
        except Exception as exc:
            raise BridgeError(
                INTERNAL_ERROR,
                f"failed to store credential: {type(exc).__name__}: {exc}",
            )
        return {"provider": provider, "logged_in": True, "label": label}

    async def _m_auth_login(self, conn, params):
        """Run a browser/device/CLI-session OAuth login inside the bridge.

        For providers whose flow completes without stdin (a loopback callback,
        a device-code poll, or reusing a local CLI session) the real
        ``fetih auth add <provider>`` path runs in a daemon thread. Its console
        output is streamed as ``auth.progress`` events (so the app can show the
        device code / URL), and a final ``auth.done`` carries the outcome and a
        refreshed status. Returns at once with the id those events carry.
        """
        provider = str(params.get("provider") or "").strip()
        # Anthropic is allowed here too: auth.login attempts the zero-paste
        # loopback flow (with auth.begin/auth.complete as the paste fallback).
        if provider != "anthropic" and provider not in _BRIDGE_BACKGROUND_AUTH:
            raise BridgeError(
                INVALID_PARAMS, f"auth.login does not handle provider '{provider}'"
            )

        loop = self.loop_for(conn) or asyncio.get_running_loop()
        request_id = uuid.uuid4().hex[:12]

        def _run() -> None:
            import contextlib
            import io
            from types import SimpleNamespace

            class _LineEmitter(io.TextIOBase):
                def writable(self) -> bool:
                    return True

                def write(self, s) -> int:
                    for line in str(s).splitlines():
                        if line.strip():
                            conn.emit_threadsafe(
                                loop,
                                event(
                                    "auth.progress",
                                    {
                                        "request_id": request_id,
                                        "provider": provider,
                                        "line": line,
                                    },
                                ),
                            )
                    return len(s)

            args = SimpleNamespace(
                provider=provider,
                auth_type=None,
                label=None,
                api_key=None,
                no_browser=False,
                timeout=None,
            )
            ok, err = True, ""
            # redirect_stdout is process-global; the lock serializes logins so
            # two of them cannot fight over sys.stdout at the same time.
            with self._auth_lock:
                try:
                    with contextlib.redirect_stdout(_LineEmitter()):
                        if provider == "anthropic":
                            # Zero-paste loopback attempt for Claude Pro/Max.
                            from agent import anthropic_adapter
                            from fetih_cli.auth_commands import persist_anthropic_oauth
                            creds = anthropic_adapter.run_fetih_oauth_loopback_login(
                                open_browser=True
                            )
                            persist_anthropic_oauth(creds)
                        else:
                            from fetih_cli.auth_commands import auth_add_command
                            auth_add_command(args)
                except SystemExit as exc:
                    ok, err = False, (str(exc) or "login aborted")
                except Exception as exc:  # noqa: BLE001 - surfaced to the app
                    ok, err = False, f"{type(exc).__name__}: {exc}"

            status: Dict[str, Any] = {}
            try:
                from fetih_cli.auth import get_auth_status
                status = get_auth_status(provider) or {}
            except Exception:
                status = {}

            conn.emit_threadsafe(
                loop,
                event(
                    "auth.done",
                    {
                        "request_id": request_id,
                        "provider": provider,
                        "ok": ok,
                        "error": err,
                        "logged_in": bool(
                            status.get("logged_in") or status.get("configured")
                        ),
                        "email": status.get("email"),
                        "plan": status.get("plan"),
                        "expires_at": status.get("expires_at"),
                    },
                ),
            )

        threading.Thread(
            target=_run, name=f"auth-login-{provider}", daemon=True
        ).start()
        return {
            "started": True,
            "request_id": request_id,
            "provider": provider,
            "flow": _AUTH_FLOW_KIND.get(provider, "background"),
        }

    def _m_auth_logout(self, conn, params):
        """Clear a provider's stored auth (pool + legacy state). Never a token."""
        provider = str(params.get("provider") or "").strip()
        if not provider:
            raise BridgeError(INVALID_PARAMS, "'provider' is required")
        try:
            from fetih_cli.auth import clear_provider_auth
            cleared = bool(clear_provider_auth(provider))
        except Exception as exc:
            raise BridgeError(CONFIG_ERROR, f"{type(exc).__name__}: {exc}")
        return {"provider": provider, "logged_out": cleared}

    # ── file.* ──────────────────────────────────────────────────────────

    #: Çalışma alanı ağacında gizlenen gürültülü dizinler.
    _FILE_TREE_SKIP = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vs",
        "bin", "obj", "dist", "build", ".next", ".turbo",
    }

    def _workspace_root(self) -> str:
        return os.path.realpath(os.getcwd())

    def _resolve_in_workspace(self, rel: str):
        """Resolve a workspace-relative path, refusing anything that escapes it.

        The file browser is scoped to the bridge's working directory so the
        desktop can't walk the whole filesystem through these RPCs.
        """
        root = self._workspace_root()
        target = os.path.realpath(os.path.join(root, rel or ""))
        if target != root and not target.startswith(root + os.sep):
            raise BridgeError(INVALID_PARAMS, "path escapes the workspace")
        return root, target

    def _m_file_tree(self, conn, params):
        """List one directory level of the workspace (lazy tree). Dirs first."""
        rel = str(params.get("path") or "")
        root, base = self._resolve_in_workspace(rel)
        if not os.path.isdir(base):
            raise BridgeError(INVALID_PARAMS, "not a directory")

        entries: List[Dict[str, Any]] = []
        try:
            for name in os.listdir(base):
                if name in self._FILE_TREE_SKIP:
                    continue
                full = os.path.join(base, name)
                is_dir = os.path.isdir(full)
                item: Dict[str, Any] = {
                    "name": name,
                    "path": os.path.relpath(full, root).replace(os.sep, "/"),
                    "is_dir": is_dir,
                }
                if not is_dir:
                    try:
                        item["size"] = os.path.getsize(full)
                    except OSError:
                        item["size"] = 0
                entries.append(item)
                if len(entries) >= 4000:
                    break
        except OSError as exc:
            raise BridgeError(INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return {
            "root": root,
            "path": rel.replace(os.sep, "/"),
            "entries": entries,
        }

    def _m_file_read(self, conn, params):
        """Return a workspace file's UTF-8 text (size-capped; binary → flagged)."""
        rel = str(params.get("path") or "")
        if not rel:
            raise BridgeError(INVALID_PARAMS, "'path' is required")
        root, target = self._resolve_in_workspace(rel)
        if not os.path.isfile(target):
            raise BridgeError(INVALID_PARAMS, "not a file")

        max_bytes = 512 * 1024
        try:
            size = os.path.getsize(target)
            with open(target, "rb") as fh:
                raw = fh.read(max_bytes + 1)
        except OSError as exc:
            raise BridgeError(INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

        truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        if b"\x00" in raw:
            return {"path": rel, "binary": True, "size": size, "content": "", "truncated": False}
        return {
            "path": rel,
            "binary": False,
            "size": size,
            "truncated": truncated,
            "content": raw.decode("utf-8", errors="replace"),
        }

    def _m_file_diff(self, conn, params):
        """Unified ``git diff`` (working tree vs HEAD) for a file or the whole tree."""
        import subprocess

        rel = str(params.get("path") or "")
        root = self._workspace_root()
        if rel:
            root, _ = self._resolve_in_workspace(rel)
            root = self._workspace_root()  # diff runs at the repo root

        args = ["git", "-C", root, "diff", "--no-color"]
        if rel:
            args += ["--", rel]
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace"
            )
        except FileNotFoundError:
            return {"path": rel, "available": False, "reason": "git not found", "diff": ""}
        except Exception as exc:  # noqa: BLE001 - reported to the app
            return {"path": rel, "available": False, "reason": f"{type(exc).__name__}: {exc}", "diff": ""}

        if proc.returncode not in (0, 1):
            reason = (proc.stderr or "").strip()[:200] or "not a git repository"
            return {"path": rel, "available": False, "reason": reason, "diff": ""}
        return {"path": rel, "available": True, "diff": proc.stdout}

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

    # ── findings.* ──────────────────────────────────────────────────────

    def _record_finding(self, conn, loop, finding: Dict[str, Any], session_id: str = "") -> bool:
        """Persist a finding and announce it. Duplicates are stored once and not re-announced."""
        row = self.findings.add(finding, session_id=session_id)
        if row is None:
            return False
        conn.emit_threadsafe(loop, event("findings.discovered", {"finding": row}))
        return True

    @staticmethod
    def _findings_filters(params) -> Dict[str, Any]:
        severity = str(params.get("severity") or "").strip()
        if severity.lower() in {"", "all", "tüm", "tüm ciddiyet seviyeleri"}:
            severity = ""
        sort = str(params.get("sort") or "severity").strip().lower()
        return {
            "severity": severity or None,
            "session_id": str(params.get("session_id") or "").strip() or None,
            "query": str(params.get("query") or "").strip() or None,
            "sort": "time" if sort == "time" else "severity",
        }

    def _m_findings_list(self, conn, params):
        findings = self.findings.list(**self._findings_filters(params))
        return {
            "total": self.findings.count(),
            "filtered": len(findings),
            "findings": findings,
        }

    def _m_findings_delete(self, conn, params):
        fid = str(params.get("id") or "").strip()
        if not fid:
            raise BridgeError(INVALID_PARAMS, "'id' is required")
        return {"deleted": self.findings.delete(fid), "id": fid}

    def _m_findings_clear(self, conn, params):
        sid = str(params.get("session_id") or "").strip() or None
        return {"cleared": self.findings.clear(sid), "session_id": sid}

    def _m_findings_export(self, conn, params):
        """Bulguları Markdown ya da HTML rapor olarak döndürür (filtreler uygulanır)."""
        fmt = str(params.get("format") or "md").lower()
        if fmt not in {"md", "markdown", "html"}:
            raise BridgeError(INVALID_PARAMS, "format must be 'md' or 'html'")
        findings = self.findings.list(**self._findings_filters(params))
        content = _build_findings_report(findings, fmt)
        return {
            "format": "html" if fmt == "html" else "md",
            "content": content,
            "count": len(findings),
        }

    def _m_findings_scan(self, conn, params):
        """Scan skills or workspace for security findings using tools.skills_guard."""
        target = params.get("target")
        from tools.skills_guard import scan_skill
        from fetih_constants import get_fetih_home

        dirs_to_scan: List[Path] = []
        if target:
            p = Path(str(target)).expanduser().resolve()
            if p.is_dir():
                dirs_to_scan.append(p)
        else:
            fetih_home = Path(get_fetih_home())
            skills_dir = fetih_home / "skills"
            if skills_dir.exists():
                dirs_to_scan.extend([d for d in skills_dir.iterdir() if d.is_dir()])
            repo_skills = Path(__file__).resolve().parents[1] / "skills"
            if repo_skills.exists():
                for cat in repo_skills.iterdir():
                    if cat.is_dir():
                        dirs_to_scan.extend([d for d in cat.iterdir() if d.is_dir()])

        new_findings: List[Dict[str, Any]] = []
        loop = self.loop_for(conn) or asyncio.get_running_loop()
        for d in dirs_to_scan[:30]:
            try:
                result = scan_skill(d, source="community")
                for f in result.findings:
                    finding_dict = {
                        "id": str(uuid.uuid4().hex[:8]),
                        "title": f"{f.category.capitalize()}: {f.description}",
                        "target": f"{f.file}:{f.line}" if f.line else f.file,
                        "severity": f.severity.capitalize(),
                        "evidence": f.match,
                        "recommendation": f"Inspect pattern {f.pattern_id} in {f.file} and remediate.",
                        "reference": f.pattern_id,
                        "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    if self._record_finding(conn, loop, finding_dict):
                        new_findings.append(finding_dict)
            except Exception:
                continue

        return {
            "scanned": len(dirs_to_scan),
            "new_findings": len(new_findings),
            "total_findings": self.findings.count(),
            "findings": self.findings.list(),
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
        session_id: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        toolsets: Optional[Any] = None,
        cwd: Optional[str] = None,
        skip_context_files: bool = False,
        skip_memory: bool = False,
    ) -> BridgeSession:
        effective_sid = (session_id or "").strip() or uuid.uuid4().hex

        if self.fake_model:
            agent = FakeModelAgent()
            return BridgeSession(
                effective_sid,
                agent,
                model="fake-simulator",
                provider="fake",
                cwd=cwd or os.getcwd(),
            )

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

        # Desktop-only Antigravity CLI backend. The CLI's provider resolver does
        # not know this id, so it is intercepted here: each turn runs Google's
        # official `agy -p` under the user's own Antigravity login.
        if effective_provider == agy_backend.PROVIDER_ID:
            agy_cfg = (cfg.get("desktop") or {}).get("antigravity") or {}
            work_dir = str(cwd) if cwd else os.getcwd()
            history: List[Dict[str, Any]] = []
            if session_id and self.store.exists(session_id):
                history = _items_to_history(self.store.items(session_id))
            return BridgeSession(
                effective_sid,
                agy_backend.AgyCliAgent(
                    model=effective_model,
                    cwd=work_dir,
                    allow_tools=bool(agy_cfg.get("allow_tools", False)),
                ),
                model=effective_model,
                provider=agy_backend.PROVIDER_ID,
                cwd=work_dir,
                history=history,
            )

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
        effective_sid = session_id or uuid.uuid4().hex[:12]

        if os.getenv("FETIH_BRIDGE_MOCK_AGENT") == "1":
            class MockAgent:
                def __init__(self):
                    self.stream_delta_callback = None
                    self.reasoning_callback = None
                    self.thinking_callback = None
                    self.tool_start_callback = None
                    self.tool_complete_callback = None
                    self._session_messages = []

                def run_conversation(self, message, conversation_history=None):
                    if self.reasoning_callback:
                        self.reasoning_callback("Thinking smoke test...")
                    if self.stream_delta_callback:
                        self.stream_delta_callback("Smoke test response delta.")
                    return {
                        "final_response": "Smoke test response delta.",
                        "reasoning": "Thinking smoke test...",
                        "api_calls": 1,
                    }

            return BridgeSession(
                effective_sid,
                MockAgent(),
                model=effective_model or "mock-model",
                provider=effective_provider or "mock-provider",
                cwd=work_dir,
            )

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
                session_id=effective_sid,
                credential_pool=runtime.get("credential_pool"),
                clarify_callback=_bridge_clarify_callback,
                skip_context_files=bool(skip_context_files),
                skip_memory=bool(skip_memory),
            )
        except Exception as exc:
            raise BridgeError(
                AGENT_ERROR, f"agent construction failed: {type(exc).__name__}: {exc}"
            )

        agent.suppress_status_output = True
        agent.tool_gen_callback = None

        # Reconstruct history from store if available
        history: List[Dict[str, Any]] = []
        if session_id and self.store.exists(session_id):
            items = self.store.items(session_id)
            history = _items_to_history(items)

        return BridgeSession(
            effective_sid,
            agent,
            model=effective_model,
            provider=str(runtime.get("provider") or effective_provider or ""),
            cwd=work_dir,
            history=history,
        )


# --- helpers ----------------------------------------------------------------


def _items_to_history(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    history: List[Dict[str, Any]] = []
    pending_tool_calls: List[Dict[str, Any]] = []

    for item in items:
        kind = item.get("kind")
        if kind == "user":
            if pending_tool_calls:
                history.append({"role": "assistant", "content": None, "tool_calls": list(pending_tool_calls)})
                pending_tool_calls = []
            history.append({"role": "user", "content": str(item.get("text") or "")})
        elif kind == "assistant":
            if pending_tool_calls:
                history.append({"role": "assistant", "content": item.get("text") or None, "tool_calls": list(pending_tool_calls)})
                pending_tool_calls = []
            else:
                history.append({"role": "assistant", "content": str(item.get("text") or "")})
        elif kind == "tool_call":
            call_id = str(item.get("call_id") or "")
            name = str(item.get("name") or "")
            args_val = item.get("args") or "{}"
            if not isinstance(args_val, str):
                args_val = json.dumps(args_val, ensure_ascii=False)
            pending_tool_calls.append({
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": args_val}
            })
        elif kind == "tool_result":
            if pending_tool_calls:
                history.append({"role": "assistant", "content": None, "tool_calls": list(pending_tool_calls)})
                pending_tool_calls = []
            call_id = str(item.get("call_id") or "")
            res_val = item.get("result")
            if not isinstance(res_val, str):
                res_val = json.dumps(res_val, ensure_ascii=False) if res_val is not None else ""
            history.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": res_val
            })

    if pending_tool_calls:
        history.append({"role": "assistant", "content": None, "tool_calls": list(pending_tool_calls)})

    return history


def _session_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """The session-shaping fields ``session.new`` and ``session.send`` share."""
    return {
        "session_id": params.get("session_id"),
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


def _safe(fn: Callable[..., Any], *args, default: Any = None, **kwargs) -> Any:
    try:
        return fn(*args, **kwargs)
    except Exception:
        return default


def _provider_model_ids_for(pid: str) -> List[str]:
    """``fetih model``'s catalog for one provider, as a plain list."""
    from fetih_cli.models import provider_model_ids

    return [str(m) for m in (provider_model_ids(pid) or [])]


def _rank_anthropic_models(ids: List[str]) -> List[str]:
    """Flagship-first ordering so the wizard's default (models[0]) is sensible.

    Newest version family first; within a version, Sonnet ahead of Opus, Haiku
    and Fable. This makes the default a balanced current model (e.g. the latest
    Sonnet) rather than whatever order the API happened to return.
    """
    import re

    def key(model: str):
        ml = model.lower()
        fam = 0 if "sonnet" in ml else 1 if "opus" in ml else 2 if "haiku" in ml else 3
        nums = re.findall(r"\d+", ml)
        major = int(nums[0]) if nums else 0
        minor = int(nums[1]) if len(nums) > 1 else 0
        # Negative → higher version sorts first.
        return (-(major * 100 + minor), fam, model)

    return sorted(ids, key=key)


def _anthropic_live_model_ids() -> List[str]:
    """Current Claude model ids from Anthropic's own ``/v1/models`` endpoint.

    Uses the resolved subscription/API token (OAuth ``sk-ant-oat*`` → Bearer,
    API key ``sk-ant-api*`` → x-api-key). Returns ``[]`` on any failure or when
    not signed in, so the caller falls back to the static catalog.
    """
    import json as _json
    import urllib.request

    from fetih_cli.runtime_provider import resolve_runtime_provider

    rt = resolve_runtime_provider(requested="anthropic", target_model=None)
    token = str(rt.get("api_key") or "").strip()
    base = str(rt.get("base_url") or "https://api.anthropic.com").strip().rstrip("/")
    if not token:
        return []

    if token.startswith("sk-ant-api"):
        headers = {"x-api-key": token, "anthropic-version": "2023-06-01"}
    else:
        headers = {
            "Authorization": f"Bearer {token}",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "oauth-2025-04-20",
            "User-Agent": "claude-cli (external, cli)",
        }

    req = urllib.request.Request(f"{base}/v1/models?limit=100", headers=headers)
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = _json.loads(resp.read().decode())
    ids = [str(m.get("id")) for m in data.get("data", []) if m.get("id")]
    return _rank_anthropic_models(ids)


#: Hosts that mean "this inference endpoint never leaves the machine".
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal")


def _is_local_endpoint(base_url: str) -> bool:
    """True when ``base_url`` points at a server on this machine.

    Drives the wizard's "don't ask for an API key" branch — a loopback
    endpoint has nobody to authenticate against.
    """
    if not base_url:
        return False
    try:
        from urllib.parse import urlparse

        host = (urlparse(base_url).hostname or "").lower()
    except Exception:
        return False
    return host in _LOCAL_HOSTS


def _provider_kind(pconfig: Any, base_url: str, auth_type: str = "") -> str:
    """Classify a provider into the setup flow it needs.

    The wizard branches on this instead of showing every provider the same
    "paste an API key" box: ``local_server`` gets an endpoint probe,
    ``cli_login`` gets a "sign in with the vendor's CLI" step, ``aws_sdk``
    defers to the ambient credential chain, and only ``cloud_api_key``
    actually needs a secret typed in.
    """
    kind_auth = auth_type or getattr(pconfig, "auth_type", "") or ""
    if _is_local_endpoint(base_url):
        return "local_server"
    if kind_auth == "aws_sdk":
        return "aws_sdk"
    if kind_auth in ("oauth_external", "oauth_device_code", "oauth_minimax", "external_process"):
        return "cli_login"
    if kind_auth in ("", "none"):
        return "no_auth"
    return "cloud_api_key"


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

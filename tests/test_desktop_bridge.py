"""Masaüstü Köprüsü — dispatch, auth gate and redaction.

Network- and agent-free: every test drives ``BridgeServer.handle_line`` through
a fake connection, so the whole RPC envelope contract is covered without
touching a provider.  The agent path itself is exercised by the live
end-to-end run documented in ``docs/masaustu-koprusu-rpc.md``.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from fetih_desktop_bridge import PROTOCOL_VERSION
from fetih_desktop_bridge.protocol import (
    CONFIG_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    SESSION_NOT_FOUND,
    UNAUTHORIZED,
    decode,
    encode,
    error,
    event,
    request,
    response,
)
from fetih_desktop_bridge.server import BridgeServer, _redact


class FakeConn:
    """Stands in for transport.Connection; records what the server sent."""

    def __init__(self, *, kind="ws", authenticated=False):
        self.kind = kind
        self.authenticated = authenticated
        self.sent = []
        self.closed = False

    async def send_frame(self, frame):
        self.sent.append(frame)

    def emit_threadsafe(self, loop, frame):
        self.sent.append(frame)

    @property
    def last(self):
        return self.sent[-1]


def drive(server, conn, method, params=None, rid=1):
    line = encode(request(rid, method, params))
    asyncio.run(server.handle_line(conn, line))
    return conn.last


# ── protocol envelope ────────────────────────────────────────────────────


def test_envelope_roundtrip():
    frame = request(7, "bridge.ping", {"a": 1})
    assert decode(encode(frame)) == frame
    assert response(7, {"ok": True})["result"] == {"ok": True}
    assert "id" not in event("session.delta", {"text": "hi"})
    assert error(7, -32000, "nope", {"x": 1})["error"]["data"] == {"x": 1}


def test_decode_rejects_non_object():
    with pytest.raises(ValueError):
        decode("[1, 2, 3]")


# ── dispatch ─────────────────────────────────────────────────────────────


def test_malformed_line_is_parse_error():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    asyncio.run(server.handle_line(conn, "{not json"))
    assert conn.last["error"]["code"] == PARSE_ERROR


def test_missing_method_is_invalid_request():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    asyncio.run(server.handle_line(conn, json.dumps({"jsonrpc": "2.0", "id": 1})))
    assert conn.last["error"]["code"] == INVALID_REQUEST


def test_unknown_method():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    assert drive(server, conn, "no.such.method")["error"]["code"] == METHOD_NOT_FOUND


def test_non_object_params_rejected():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    asyncio.run(
        server.handle_line(
            conn, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "bridge.ping", "params": []})
        )
    )
    assert conn.last["error"]["code"] == INVALID_PARAMS


def test_notification_gets_no_reply():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    asyncio.run(
        server.handle_line(conn, json.dumps({"jsonrpc": "2.0", "method": "bridge.ping"}))
    )
    assert conn.sent == []


def test_ping_and_capabilities():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    assert drive(server, conn, "bridge.ping")["result"]["pong"] is True

    caps = drive(server, conn, "bridge.capabilities")["result"]
    assert caps["protocol_version"] == PROTOCOL_VERSION
    assert caps["min_supported_version"] <= caps["max_supported_version"]
    for name in ("session.send", "config.get", "config.set",
                 "providers.list", "skills.list", "diagnostics.info"):
        assert name in caps["methods"]
    for name in ("session.delta", "session.tool_call", "session.tool_result",
                 "session.done", "session.error"):
        assert name in caps["events"]


# ── auth gate ────────────────────────────────────────────────────────────


def test_ws_requires_auth_before_privileged_methods():
    server = BridgeServer(token="s3cret", require_auth=True)
    conn = FakeConn(kind="ws", authenticated=False)
    assert drive(server, conn, "diagnostics.info")["error"]["code"] == UNAUTHORIZED
    # ...but the handshake trio is reachable.
    assert drive(server, conn, "bridge.ping")["result"]["pong"] is True
    assert drive(server, conn, "bridge.capabilities")["result"]["auth_required"] is True


def test_wrong_token_rejected_right_token_accepted():
    server = BridgeServer(token="s3cret", require_auth=True)
    conn = FakeConn(kind="ws", authenticated=False)

    assert drive(server, conn, "bridge.authenticate", {"token": "nope"})["error"]["code"] == UNAUTHORIZED
    assert conn.authenticated is False

    assert drive(server, conn, "bridge.authenticate", {"token": "s3cret"})["result"]["authenticated"] is True
    assert conn.authenticated is True
    assert "result" in drive(server, conn, "diagnostics.info")


def test_stdio_is_preauthenticated():
    server = BridgeServer(token="s3cret", require_auth=False)
    conn = FakeConn(kind="stdio", authenticated=True)
    assert "result" in drive(server, conn, "diagnostics.info")


# ── redaction ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("key", ["api_key", "apiKey", "GROQ_TOKEN", "client_secret", "password"])
def test_secret_leaves_are_redacted(key):
    assert _redact({key: "sk-live-abc123"})[key] == "<redacted>"


def test_env_references_are_not_secrets():
    # "${GROQ_API_KEY}" is a variable NAME; the UI needs to show it.
    assert _redact({"api_key": "${GROQ_API_KEY}"})["api_key"] == "${GROQ_API_KEY}"


def test_redaction_is_recursive_and_preserves_shape():
    src = {
        "providers": {"groq": {"base_url": "https://api.groq.com", "api_key": "sk-x"}},
        "list": [{"token": "t"}, {"name": "keep"}],
        "n": 5,
    }
    out = _redact(src)
    assert out["providers"]["groq"]["api_key"] == "<redacted>"
    assert out["providers"]["groq"]["base_url"] == "https://api.groq.com"
    assert out["list"][0]["token"] == "<redacted>"
    assert out["list"][1]["name"] == "keep"
    assert out["n"] == 5
    assert src["providers"]["groq"]["api_key"] == "sk-x", "input must not be mutated"


def test_config_set_refuses_credential_keys():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    err = drive(server, conn, "config.set",
                {"key": "auxiliary.vision.api_key", "value": "sk-x"})["error"]
    assert err["code"] == CONFIG_ERROR


def test_config_set_validates_params():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    assert drive(server, conn, "config.set", {"value": 1})["error"]["code"] == INVALID_PARAMS
    assert drive(server, conn, "config.set", {"key": "a.b"})["error"]["code"] == INVALID_PARAMS


# ── sessions ─────────────────────────────────────────────────────────────


def test_unknown_session_id():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    for method in ("session.close", "session.cancel"):
        assert drive(server, conn, method, {"session_id": "ghost"})["error"]["code"] == SESSION_NOT_FOUND
    assert drive(server, conn, "session.send",
                 {"session_id": "ghost", "message": "hi"})["error"]["code"] == SESSION_NOT_FOUND


def test_empty_message_rejected_before_any_agent_work():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    err = drive(server, conn, "session.send", {"message": "   "})["error"]
    assert err["code"] == INVALID_PARAMS
    assert server.sessions == {}, "a rejected send must not leave a session behind"


def test_session_list_starts_empty():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    assert drive(server, conn, "session.list")["result"]["sessions"] == []


# ── read-only introspection works without a provider ─────────────────────


def test_diagnostics_info_shape():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(kind="stdio", authenticated=True)
    info = drive(server, conn, "diagnostics.info")["result"]
    assert info["protocol_version"] == PROTOCOL_VERSION
    assert info["bridge"]["transport"] == "stdio"
    assert info["python"]["version"]
    assert "config" in info["paths"] and "repo_root" in info["paths"]


def test_skills_list_is_paged_and_categorised():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    res = drive(server, conn, "skills.list", {"limit": 3})["result"]
    assert res["limit"] == 3
    assert len(res["skills"]) <= 3
    assert isinstance(res["categories"], dict)
    assert res["total"] >= len(res["skills"])
    for s in res["skills"]:
        assert {"name", "description", "category", "source"} <= set(s)


# ── providers.catalog / .models / .probe_local / .auth_status ────────────
#
# These four exist so the desktop shell stops guessing. Before them the app
# answered "which providers exist?" and "which models exist?" from tables
# compiled into the C# binary; both drifted from what the runtime actually
# accepted, and the drift only surfaced as a failed first chat message.


def test_providers_catalog_serves_the_canonical_registry():
    from fetih_cli.auth import PROVIDER_REGISTRY

    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    res = drive(server, conn, "providers.catalog")["result"]

    ids = {p["id"] for p in res["providers"]}
    assert res["count"] == len(res["providers"])
    assert "groq" in ids, "groq must be offerable — its absence was the original bug"
    assert "ollama" in ids

    # Canonical ids only: aliases ride along on their owner's row.
    assert "groqcloud" not in ids
    groq = next(p for p in res["providers"] if p["id"] == "groq")
    assert "groqcloud" in groq["aliases"]

    # Every advertised id must be one the resolver accepts.
    for pid in ids:
        assert pid in PROVIDER_REGISTRY or pid in {"openrouter", "custom", "local"}


def test_providers_catalog_classifies_setup_flow():
    """The wizard branches on `kind`; a mislabelled provider asks the wrong question."""
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    rows = {p["id"]: p for p in drive(server, conn, "providers.catalog")["result"]["providers"]}

    assert rows["groq"]["kind"] == "cloud_api_key"
    assert rows["ollama"]["kind"] == "local_server" and rows["ollama"]["is_local"]
    assert rows["lmstudio"]["kind"] == "local_server"
    # Hosted Ollama is NOT local — it must keep asking for a key.
    assert rows["ollama-cloud"]["kind"] == "cloud_api_key"
    assert not rows["ollama-cloud"]["is_local"]
    assert rows["google-gemini-cli"]["kind"] == "cli_login"
    assert rows["openai-codex"]["kind"] == "cli_login"
    assert rows["bedrock"]["kind"] == "aws_sdk"


def test_providers_catalog_never_leaks_a_secret():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    for p in drive(server, conn, "providers.catalog")["result"]["providers"]:
        # Env var NAMES are fine; values must never appear.
        assert "api_key" not in p or isinstance(p.get("api_key_env_vars"), list)
        assert "token" not in p


def test_providers_models_requires_a_provider():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    err = drive(server, conn, "providers.models", {})["error"]
    assert err["code"] == INVALID_PARAMS


def test_providers_models_recommends_a_tool_capable_model():
    """models[0] is what the wizard writes as model.default, so it must be usable."""
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    res = drive(server, conn, "providers.models", {"provider": "groq"})["result"]

    assert res["provider"] == "groq"
    assert res["models"], "groq must always offer at least the offline seed"
    assert res["recommended"] == res["models"][0]
    # Transcription / speech / classifier models cannot drive the agent loop
    # and must never be the default.
    assert not res["recommended"].startswith(("whisper", "canopylabs/"))
    assert "llama-3.3-70b-versatile" not in res["models"][:1]


def test_providers_probe_local_reports_a_dead_endpoint_as_dead():
    """No server on that port must read as 'not running', not as an RPC error."""
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    res = drive(server, conn, "providers.probe_local",
                {"provider": "ollama", "base_url": "http://127.0.0.1:1", "timeout": 1})["result"]

    assert res["running"] is False
    assert res["models"] == []
    assert res["detail"]


def test_providers_probe_local_rejects_unknown_provider():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    err = drive(server, conn, "providers.probe_local", {"provider": "no-such-thing"})["error"]
    assert err["code"] == INVALID_PARAMS


def test_providers_auth_status_is_presence_only():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)
    res = drive(server, conn, "providers.auth_status", {"provider": "google-gemini-cli"})["result"]

    assert res["provider"] == "google-gemini-cli"
    assert isinstance(res["logged_in"], bool)
    # Whatever the CLI's status dict carries, no credential material crosses.
    for key in res:
        assert not any(hint in key.lower() for hint in ("token", "secret", "api_key", "password"))


def test_findings_list_and_scan():
    server = BridgeServer(require_auth=False)
    conn = FakeConn(authenticated=True)

    # Initial list is empty
    res = drive(server, conn, "findings.list")["result"]
    assert res["total"] == 0
    assert res["findings"] == []

    # Run scan
    scan_res = drive(server, conn, "findings.scan")["result"]
    assert "scanned" in scan_res
    assert "total_findings" in scan_res
    assert isinstance(scan_res["findings"], list)

    # Subsequent list returns findings
    list_res = drive(server, conn, "findings.list")["result"]
    assert list_res["total"] == scan_res["total_findings"]

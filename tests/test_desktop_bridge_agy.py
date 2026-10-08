"""Tests for the Antigravity CLI (`agy`) desktop-bridge backend.

No real `agy` is spawned: a fake Popen stands in for the process so every
branch (success, auto-denied tool, non-zero exit, oversize prompt, cancel)
runs deterministically and offline.
"""

import io
import types

import pytest

from fetih_desktop_bridge import agy_backend
from fetih_desktop_bridge.agy_backend import AgyCliAgent, compose_prompt


class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.returncode = returncode
        self.killed = False

    def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


def _popen_returning(proc, calls):
    def _popen(args, **kwargs):
        calls.append(args)
        return proc

    return _popen


def _agent(proc, calls, **kw):
    return AgyCliAgent(
        model=kw.pop("model", "gemini-3.6-flash-low"),
        cwd=".",
        popen=_popen_returning(proc, calls),
        exe="agy",
        **kw,
    )


# ── prompt composition ────────────────────────────────────────────────────


def test_compose_prompt_without_history_is_the_message():
    assert compose_prompt("merhaba", None) == "merhaba"
    assert compose_prompt("merhaba", []) == "merhaba"


def test_compose_prompt_folds_user_and_assistant_turns_only():
    history = [
        {"role": "system", "content": "gizli sistem"},
        {"role": "user", "content": "ilk soru"},
        {"role": "assistant", "content": "ilk cevap"},
        {"role": "tool", "content": "araç çıktısı"},
    ]
    prompt = compose_prompt("ikinci soru", history)
    assert "ilk soru" in prompt and "ilk cevap" in prompt
    assert "gizli sistem" not in prompt and "araç çıktısı" not in prompt
    assert prompt.rstrip().endswith("ikinci soru")


def test_compose_prompt_caps_history_size():
    history = [{"role": "user", "content": "x" * 5000} for _ in range(10)]
    prompt = compose_prompt("son", history)
    assert len(prompt) < 13000


# ── a turn ─────────────────────────────────────────────────────────────────


def test_successful_turn_streams_and_records_history():
    calls, deltas = [], []
    proc = _FakeProc(stdout="Merhaba!\nNasıl yardımcı olabilirim?\n")
    agent = _agent(proc, calls)
    agent.stream_delta_callback = deltas.append

    res = agent.run_conversation("selam")

    assert res["final_response"] == "Merhaba!\nNasıl yardımcı olabilirim?"
    assert "failed" not in res
    assert "".join(deltas).startswith("Merhaba!")
    args = calls[0]
    assert args[:3] == ["agy", "-p", "selam"]
    assert "--model" in args and "gemini-3.6-flash-low" in args
    assert "--dangerously-skip-permissions" not in args
    assert agent._session_messages[-2:] == [
        {"role": "user", "content": "selam"},
        {"role": "assistant", "content": "Merhaba!\nNasıl yardımcı olabilirim?"},
    ]


def test_allow_tools_passes_skip_permissions_flag():
    calls = []
    agent = _agent(_FakeProc(stdout="tamam\n"), calls, allow_tools=True)
    agent.run_conversation("listele")
    assert "--dangerously-skip-permissions" in calls[0]


def test_auto_denied_tool_becomes_explanation_not_empty_reply():
    stderr = (
        'jetski: no output produced — a tool required the "command" permission '
        "that headless mode cannot prompt for, so it was auto-denied."
    )
    agent = _agent(_FakeProc(stdout="", stderr=stderr), [])
    res = agent.run_conversation("dosyaları listele")
    assert "failed" not in res
    assert "allow_tools" in res["final_response"]


def test_nonzero_exit_is_a_failed_turn():
    agent = _agent(_FakeProc(stdout="", stderr="not signed in", returncode=1), [])
    res = agent.run_conversation("selam")
    assert res["failed"] is True
    assert "not signed in" in res["error"]


def test_oversize_prompt_fails_before_spawning():
    calls = []
    agent = _agent(_FakeProc(stdout="never"), calls)
    res = agent.run_conversation("x" * (agy_backend._MAX_PROMPT_CHARS + 10))
    assert res["failed"] is True
    assert calls == []


def test_history_is_dropped_when_message_plus_history_exceed_limit():
    # History alone is capped at ~12K; a long message on top of it pushes the
    # prompt past the command-line budget, so the folded history goes first.
    calls = []
    agent = _agent(_FakeProc(stdout="ok\n"), calls)
    history = [{"role": "user", "content": "y" * 40000}]
    message = "m" * 20000
    res = agent.run_conversation(message, conversation_history=history)
    assert res["final_response"] == "ok"
    assert calls[0][2] == message


def test_interrupt_kills_process_and_marks_cancelled():
    proc = _FakeProc()
    agent = _agent(proc, [])

    def _stdout():
        yield "kısmi\n"
        agent.interrupt()  # cancel arrives while agy is still running
        yield "devamı\n"

    proc.stdout = _stdout()
    res = agent.run_conversation("uzun iş")
    assert proc.killed is True
    assert res["failed"] is True and res["error"] == "cancelled"


# ── models / status ───────────────────────────────────────────────────────


def test_list_models_parses_and_caches(monkeypatch):
    monkeypatch.setattr(agy_backend, "find_agy", lambda: "agy")
    agy_backend._models_cache.update({"at": 0.0, "models": []})
    runs = []

    def runner(args, **kwargs):
        runs.append(args)
        return types.SimpleNamespace(
            returncode=0, stdout="gemini-3.6-flash-low\nclaude-opus-5-5-high\n\n"
        )

    assert agy_backend.list_models(refresh=True, runner=runner) == [
        "gemini-3.6-flash-low",
        "claude-opus-5-5-high",
    ]
    assert agy_backend.list_models(runner=runner) == [
        "gemini-3.6-flash-low",
        "claude-opus-5-5-high",
    ]
    assert len(runs) == 1  # second call served from cache


def test_list_models_empty_when_agy_missing(monkeypatch):
    monkeypatch.setattr(agy_backend, "find_agy", lambda: None)
    assert agy_backend.list_models(refresh=True) == []
    assert agy_backend.status()["logged_in"] is False


def test_list_models_empty_when_not_signed_in(monkeypatch):
    monkeypatch.setattr(agy_backend, "find_agy", lambda: "agy")
    runner = lambda args, **kw: types.SimpleNamespace(returncode=1, stdout="")
    assert agy_backend.list_models(refresh=True, runner=runner) == []


# ── bridge wiring ─────────────────────────────────────────────────────────


@pytest.fixture
def server():
    from fetih_desktop_bridge.server import BridgeServer

    return BridgeServer(require_auth=False)


def test_build_session_uses_agy_agent_for_antigravity_provider(server):
    session = server._build_session(
        provider=agy_backend.PROVIDER_ID, model="gemini-3.6-flash-low"
    )
    assert isinstance(session.agent, AgyCliAgent)
    assert session.provider == agy_backend.PROVIDER_ID
    assert session.agent.allow_tools is False  # default: tools stay denied


def test_auth_status_and_models_route_to_agy_backend(server, monkeypatch):
    monkeypatch.setattr(
        agy_backend, "status", lambda: {"provider": "antigravity-cli", "logged_in": True}
    )
    monkeypatch.setattr(agy_backend, "list_models", lambda **kw: ["gemini-3.1-pro-high"])
    st = server._m_providers_auth_status(None, {"provider": agy_backend.PROVIDER_ID})
    assert st["logged_in"] is True
    models = server._m_providers_models(None, {"provider": agy_backend.PROVIDER_ID})
    assert models["models"] == ["gemini-3.1-pro-high"]
    assert models["recommended"] == "gemini-3.1-pro-high"


def test_catalog_offers_agy_only_when_installed(server, monkeypatch):
    monkeypatch.setattr(agy_backend, "find_agy", lambda: None)
    ids = {p["id"] for p in server._m_providers_catalog(None, {})["providers"]}
    assert agy_backend.PROVIDER_ID not in ids

    monkeypatch.setattr(agy_backend, "find_agy", lambda: "agy")
    ids = {p["id"] for p in server._m_providers_catalog(None, {})["providers"]}
    assert agy_backend.PROVIDER_ID in ids

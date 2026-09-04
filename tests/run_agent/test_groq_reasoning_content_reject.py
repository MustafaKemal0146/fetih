"""Regression test: Groq REJECTS ``reasoning_content`` echo-back.

The inverse of the DeepSeek/Kimi/MiMo case covered in
``test_deepseek_reasoning_content_echo.py``.  Groq's OpenAI-compatible API
validates the Chat Completions schema strictly.  Reasoning-emitting models
served there (``openai/gpt-oss-*``, ``qwen/qwen3.*``) stream a ``reasoning``
field, but replaying it back as ``reasoning_content`` on the assistant
tool-call message fails with HTTP 400::

    'messages.N' : for 'role:assistant' the following must be satisfied
    [('messages.N' : property 'reasoning_content' is unsupported)]

which breaks *every* multi-turn tool-calling conversation on Groq: the first
request succeeds, the tool runs, and the replay of the assistant turn 400s.

Verified against the live API on 2026-09-05 with ``openai/gpt-oss-20b``:
echoing the field returned exactly the 400 above; running the same history
through ``copy_reasoning_content_for_api`` first returned 200.

Detection is host-driven, not model-name-driven — aggregators that re-export
the same models speak their own protocol and must not inherit Groq's rule.
"""

from __future__ import annotations

import pytest

from agent.agent_runtime_helpers import copy_reasoning_content_for_api
from run_agent import AIAgent


def _make_agent(provider: str = "", model: str = "", base_url: str = "") -> AIAgent:
    agent = object.__new__(AIAgent)
    agent.provider = provider
    agent.model = model
    agent.base_url = base_url
    agent.verbose_logging = False
    return agent


# ── detection ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.groq.com/openai/v1",
        "https://api.groq.com/openai/v1/",
        "https://api.groq.com",
    ],
)
def test_groq_host_rejects_echo(base_url):
    agent = _make_agent(provider="custom", model="openai/gpt-oss-120b", base_url=base_url)
    assert agent._rejects_reasoning_content_echo() is True


@pytest.mark.parametrize(
    "provider,model,base_url",
    [
        # An aggregator re-exporting the same model is NOT Groq.
        ("openrouter", "openai/gpt-oss-120b", "https://openrouter.ai/api/v1"),
        # Providers that REQUIRE the echo must never be caught by this rule.
        ("deepseek", "deepseek-chat", "https://api.deepseek.com"),
        ("kimi-coding", "kimi-k2", "https://api.kimi.com/v1"),
        # A look-alike host must not match.
        ("custom", "openai/gpt-oss-120b", "https://api.groq.com.evil.example/v1"),
        ("", "", ""),
    ],
)
def test_non_groq_hosts_do_not_reject_echo(provider, model, base_url):
    agent = _make_agent(provider=provider, model=model, base_url=base_url)
    assert agent._rejects_reasoning_content_echo() is False


# ── replay behaviour ─────────────────────────────────────────────────────


def _groq_agent() -> AIAgent:
    return _make_agent(
        provider="custom",
        model="openai/gpt-oss-120b",
        base_url="https://api.groq.com/openai/v1",
    )


def test_groq_replay_strips_reasoning_content_on_tool_call_turn():
    """The exact shape that 400s: assistant + tool_calls + reasoning."""
    agent = _groq_agent()
    source = {
        "role": "assistant",
        "content": "",
        "reasoning": "The user wants the time. I should call get_time.",
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_time", "arguments": "{}"}}],
    }
    api_msg = {
        "role": "assistant",
        "content": "",
        "tool_calls": source["tool_calls"],
        "reasoning_content": source["reasoning"],
        "reasoning": source["reasoning"],
    }

    copy_reasoning_content_for_api(agent, source, api_msg)

    assert "reasoning_content" not in api_msg
    assert "reasoning" not in api_msg
    # Everything the API *does* need survives untouched.
    assert api_msg["tool_calls"] == source["tool_calls"]
    assert api_msg["role"] == "assistant"


def test_groq_replay_strips_even_when_source_pinned_reasoning_content():
    """Poisoned history (recorded under a provider that pins the field) must
    still be cleaned before it reaches Groq — the early return has to run
    BEFORE the 'preserve existing verbatim' branch."""
    agent = _groq_agent()
    source = {
        "role": "assistant",
        "content": "",
        "reasoning_content": " ",  # DeepSeek/Kimi-style placeholder
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "terminal", "arguments": "{}"}}],
    }
    api_msg = {"role": "assistant", "content": "",
               "tool_calls": source["tool_calls"], "reasoning_content": " "}

    copy_reasoning_content_for_api(agent, source, api_msg)

    assert "reasoning_content" not in api_msg


def test_groq_replay_strips_on_plain_text_turn():
    """Not only tool-call turns: a plain assistant turn carrying reasoning is
    replayed on the next user message and would 400 just the same."""
    agent = _groq_agent()
    source = {"role": "assistant", "content": "Hello.", "reasoning": "Greeting."}
    api_msg = {"role": "assistant", "content": "Hello.", "reasoning_content": "Greeting."}

    copy_reasoning_content_for_api(agent, source, api_msg)

    assert "reasoning_content" not in api_msg
    assert api_msg["content"] == "Hello."


def test_non_assistant_messages_untouched():
    agent = _groq_agent()
    source = {"role": "tool", "tool_call_id": "c1", "content": "14:05"}
    api_msg = dict(source)

    copy_reasoning_content_for_api(agent, source, api_msg)

    assert api_msg == source


def test_deepseek_still_receives_reasoning_content():
    """Guard against the Groq early-return regressing the providers that
    REQUIRE the field."""
    agent = _make_agent(provider="deepseek", model="deepseek-chat",
                        base_url="https://api.deepseek.com")
    source = {
        "role": "assistant",
        "content": "",
        "reasoning": "thinking",
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "terminal", "arguments": "{}"}}],
    }
    api_msg = {"role": "assistant", "content": "", "tool_calls": source["tool_calls"]}

    copy_reasoning_content_for_api(agent, source, api_msg)

    assert api_msg.get("reasoning_content"), "DeepSeek must keep reasoning_content"

"""Unit and integration tests for context pruning (Issue #64).

Tests:
  - ContextCompressor.prune_only preserves the last 2 user turns + protect_tail_tokens
  - Preserves skill_view tool results
  - Replaces pruned tool results with informative placeholders
  - Preserves tool_call_id parity
  - Does not double-prune already pruned results
  - conversation_loop integration when prune_enabled or bridge session
  - Bridge session.compress RPC handler
"""

import json
import logging
import pytest
from unittest.mock import patch, MagicMock

from agent.context_compressor import ContextCompressor


@pytest.fixture
def compressor():
    return ContextCompressor(quiet_mode=True)


class TestPruneOnly:
    def test_empty_messages(self, compressor):
        msgs, count = compressor.prune_only([])
        assert msgs == []
        assert count == 0

    def test_protects_last_two_user_turns_by_default(self, compressor):
        """Messages within the last 2 user turns are never pruned.
        Earlier tool outputs outside those 2 turns are pruned."""
        messages = [
            {"role": "user", "content": "First turn user message"},
            {"role": "assistant", "content": "Calling tool 1", "tool_calls": [
                {"id": "call_1", "function": {"name": "read_file", "arguments": json.dumps({"path": "src/old.py"})}}
            ]},
            {"role": "tool", "tool_call_id": "call_1", "name": "read_file", "content": "Old source code content here..." * 20},
            {"role": "assistant", "content": "Done with turn 1"},
            
            # Turn 2 (second to last user turn - protected)
            {"role": "user", "content": "Second turn user message"},
            {"role": "assistant", "content": "Calling tool 2", "tool_calls": [
                {"id": "call_2", "function": {"name": "terminal", "arguments": json.dumps({"command": "ls -la"})}}
            ]},
            {"role": "tool", "tool_call_id": "call_2", "name": "terminal", "content": "total 42\nfile1\nfile2"},
            
            # Turn 3 (last user turn - protected)
            {"role": "user", "content": "Third turn user message"},
            {"role": "assistant", "content": "Calling tool 3", "tool_calls": [
                {"id": "call_3", "function": {"name": "read_file", "arguments": json.dumps({"path": "src/current.py"})}}
            ]},
            {"role": "tool", "tool_call_id": "call_3", "name": "read_file", "content": "Current active code"},
        ]

        pruned, count = compressor.prune_only(messages)
        assert count == 1  # only call_1 in turn 1 is pruned

        # call_1 is replaced with placeholder
        t1 = pruned[2]
        assert t1["tool_call_id"] == "call_1"
        assert t1["role"] == "tool"
        assert "[Eski araç çıktısı temizlendi: read_file src/old.py" in t1["content"]
        assert "karakter]" in t1["content"]

        # Turn 2 and 3 tool outputs must remain intact
        assert pruned[6]["content"] == "total 42\nfile1\nfile2"
        assert pruned[9]["content"] == "Current active code"

    def test_preserves_skill_view_outputs(self, compressor):
        """skill_view outputs in older turns must NEVER be pruned."""
        messages = [
            {"role": "user", "content": "Old request"},
            {"role": "assistant", "content": "Checking skill", "tool_calls": [
                {"id": "call_skill", "function": {"name": "skill_view", "arguments": json.dumps({"name": "deploy"})}},
                {"id": "call_term", "function": {"name": "terminal", "arguments": json.dumps({"command": "echo 1"})}},
            ]},
            {"role": "tool", "tool_call_id": "call_skill", "name": "skill_view", "content": "Important skill code instructions"},
            {"role": "tool", "tool_call_id": "call_term", "name": "terminal", "content": "Output 1" * 15},
            {"role": "user", "content": "Mid user message"},
            {"role": "assistant", "content": "Mid response"},
            {"role": "user", "content": "Latest user message"},
        ]

        pruned, count = compressor.prune_only(messages)
        assert count == 1  # only terminal was pruned

        skill_tool = pruned[2]
        assert skill_tool["content"] == "Important skill code instructions"

        term_tool = pruned[3]
        assert "[Eski araç çıktısı temizlendi: terminal echo 1" in term_tool["content"]
        assert term_tool["tool_call_id"] == "call_term"

    def test_maintains_tool_call_id_parity(self, compressor):
        """Pruned message retains role='tool' and exact tool_call_id."""
        messages = [
            {"role": "user", "content": "msg 1"},
            {"role": "assistant", "content": "tool calling", "tool_calls": [
                {"id": "call_abc_123", "function": {"name": "read_file", "arguments": '{"path": "data.txt"}'}}
            ]},
            {"role": "tool", "tool_call_id": "call_abc_123", "name": "read_file", "content": "Lots of data" * 10},
            {"role": "user", "content": "msg 2"},
            {"role": "assistant", "content": "resp 2"},
            {"role": "user", "content": "msg 3"},
        ]

        pruned, count = compressor.prune_only(messages)
        assert count == 1
        assert pruned[2]["tool_call_id"] == "call_abc_123"
        assert pruned[2]["role"] == "tool"
        assert pruned[2]["name"] == "read_file"

    def test_protect_tail_tokens(self, compressor):
        """When protect_tail_tokens is given, tail messages within that token budget are protected."""
        messages = [
            {"role": "user", "content": "Turn 1"},
            {"role": "assistant", "content": "a", "tool_calls": [
                {"id": "c1", "function": {"name": "read_file", "arguments": '{"path": "f1.txt"}'}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "X" * 100},
            {"role": "user", "content": "Turn 2"},
            {"role": "assistant", "content": "b", "tool_calls": [
                {"id": "c2", "function": {"name": "read_file", "arguments": '{"path": "f2.txt"}'}}
            ]},
            {"role": "tool", "tool_call_id": "c2", "content": "Y" * 100},
            {"role": "user", "content": "Turn 3"},
            {"role": "assistant", "content": "c", "tool_calls": [
                {"id": "c3", "function": {"name": "read_file", "arguments": '{"path": "f3.txt"}'}}
            ]},
            {"role": "tool", "tool_call_id": "c3", "content": "Z" * 100},
            {"role": "user", "content": "Turn 4"},
        ]

        # Very generous protect_tail_tokens covers all turns
        pruned, count = compressor.prune_only(messages, protect_tail_tokens=50000)
        assert count == 0

    def test_double_prune_idempotent(self, compressor):
        """Calling prune_only multiple times should not re-prune already pruned items."""
        messages = [
            {"role": "user", "content": "Turn 1"},
            {"role": "assistant", "content": "a", "tool_calls": [
                {"id": "c1", "function": {"name": "terminal", "arguments": '{"command": "dir"}'}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "Result " * 20},
            {"role": "user", "content": "Turn 2"},
            {"role": "user", "content": "Turn 3"},
        ]

        pruned1, count1 = compressor.prune_only(messages)
        assert count1 == 1

        pruned2, count2 = compressor.prune_only(pruned1)
        assert count2 == 0
        assert pruned2[2]["content"] == pruned1[2]["content"]


class TestBridgeSessionCompressRPC:
    def test_session_compress_rpc(self, tmp_path):
        from fetih_desktop_bridge.server import BridgeServer

        server = BridgeServer(store_path=str(tmp_path / "test.db"), fake_model=True)
        conn = MagicMock()
        conn.authenticated = True

        sid = server.store.create(title="Compression Test")
        session = server._build_session(session_id=sid)
        server.sessions[sid] = session

        # Add history with old tool result
        session.history = [
            {"role": "user", "content": "Old request"},
            {"role": "assistant", "content": "running command", "tool_calls": [
                {"id": "c1", "function": {"name": "read_file", "arguments": '{"path": "a.txt"}'}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "name": "read_file", "content": "Large file content " * 50},
            {"role": "user", "content": "Recent request 1"},
            {"role": "assistant", "content": "Recent answer 1"},
            {"role": "user", "content": "Recent request 2"},
        ]

        res = server._m_session_compress(conn, {"session_id": sid})
        assert res["session_id"] == sid
        assert res["pruned_count"] == 1
        assert res["tokens_after"] > 0
        assert "[Eski araç çıktısı temizlendi: read_file a.txt" in session.history[2]["content"]

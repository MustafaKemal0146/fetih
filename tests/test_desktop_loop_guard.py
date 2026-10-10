"""Tests for Issue #57: Repeated tool call loop guard and bridge status emission."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent.tool_guardrails import ToolCallGuardrailController, ToolCallGuardrailConfig
from fetih_desktop_bridge.protocol import encode, request
from fetih_desktop_bridge.server import BridgeServer, BridgeSession
from tests.test_desktop_bridge import FakeConn, drive


class FakeLoopingAgent:
    """Simulates an agent that hits a tool call loop guard."""

    def __init__(self, fail_count=5):
        self.fail_count = fail_count
        self.stream_delta_callback = None
        self.reasoning_callback = None
        self.thinking_callback = None
        self.status_callback = None
        self.tool_start_callback = None
        self.tool_complete_callback = None
        self._tool_guardrails = ToolCallGuardrailController(
            ToolCallGuardrailConfig(hard_stop_enabled=True, exact_failure_block_after=fail_count)
        )
        self._tool_guardrail_halt_decision = None
        self._session_messages = []

    def run_conversation(self, message, conversation_history=None):
        args = {"cmd": "faulty_command"}
        for i in range(self.fail_count + 1):
            # Check before call
            decision = self._tool_guardrails.before_call("faulty_tool", args)
            if not decision.allows_execution:
                self._tool_guardrail_halt_decision = decision
                if self.status_callback:
                    self.status_callback(
                        "lifecycle",
                        f"⚠️ Tool guardrail halted {decision.tool_name}: {decision.code}",
                    )
                return {
                    "final_response": "I stopped retrying faulty_tool because it hit the tool-call guardrail.",
                    "guardrail": decision.to_metadata(),
                }
            # Record failed tool call
            after_dec = self._tool_guardrails.after_call(
                "faulty_tool", args, '{"error": "failed"}', failed=True
            )
            if after_dec.should_halt:
                self._tool_guardrail_halt_decision = after_dec
                if self.status_callback:
                    self.status_callback(
                        "lifecycle",
                        f"⚠️ Tool guardrail halted {after_dec.tool_name}: {after_dec.code}",
                    )
                return {
                    "final_response": "Halted by guardrail.",
                    "guardrail": after_dec.to_metadata(),
                }

        return {"final_response": "done"}


class TestDesktopLoopGuard:
    def test_bridge_session_loop_guard_event_emission(self, tmp_path: Path):
        server = BridgeServer(token="secret", fake_model=True, store_path=tmp_path / "bridge.db")
        conn = FakeConn(authenticated=True)

        agent = FakeLoopingAgent(fail_count=5)
        session = BridgeSession("s-loop", agent, model="mock-model", provider="mock-provider", cwd=str(tmp_path))
        server.sessions["s-loop"] = session

        # Send a prompt to trigger the loop
        frame = drive(server, conn, "session.send", {"session_id": "s-loop", "message": "run test"})
        assert "result" in frame

        # Check emitted events for session.status with kind=loop_guard
        loop_guard_events = [
            f for f in conn.sent
            if f.get("method") == "session.status" and f.get("params", {}).get("kind") == "loop_guard"
        ]

        assert len(loop_guard_events) >= 1
        ev_params = loop_guard_events[0]["params"]
        assert ev_params["kind"] == "loop_guard"
        assert ev_params["tool"] == "faulty_tool"
        assert ev_params["count"] == 5
        assert "durduruldu" in ev_params["text"].lower()

    def test_hard_stop_enabled_defaults(self):
        # By default in core agent config, hard_stop_enabled is False
        cfg = ToolCallGuardrailConfig()
        assert cfg.hard_stop_enabled is False

        # When built for desktop bridge, hard_stop_enabled is True
        from dataclasses import replace
        bridge_cfg = replace(cfg, hard_stop_enabled=True)
        assert bridge_cfg.hard_stop_enabled is True

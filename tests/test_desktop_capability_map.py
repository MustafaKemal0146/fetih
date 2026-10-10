"""Unit tests for Capability Map and use_tool Bridge (Issue #75 Faz 1-3).

Tests:
  - use_tool execution with canonical tools
  - Wire aliases normalization (bash -> terminal, python -> execute_code, cat -> read_file)
  - Groq tool_use_failed and JSON string arguments recovery
  - Recursion guard for use_tool
  - build_capability_map() structured output
  - Bridge RPC methods: skills.map and capabilities.map
  - Toolset registry registration for use_tool
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from tools.capability_map import (
    WIRE_TOOL_ALIASES,
    build_capability_map,
    normalize_tool_name,
    parse_tool_arguments,
    use_tool,
)
from toolsets import TOOLSETS, get_toolset
from tools.registry import registry
from fetih_desktop_bridge.server import BridgeServer


class TestToolNameNormalization:
    def test_wire_aliases(self):
        assert normalize_tool_name("bash") == "terminal"
        assert normalize_tool_name("sh") == "terminal"
        assert normalize_tool_name("shell") == "terminal"
        assert normalize_tool_name("python") == "execute_code"
        assert normalize_tool_name("run_python") == "execute_code"
        assert normalize_tool_name("cat") == "read_file"
        assert normalize_tool_name("view") == "read_file"
        assert normalize_tool_name("edit") == "patch"
        assert normalize_tool_name("str_replace_editor") == "patch"
        assert normalize_tool_name("search_web") == "web_search"
        assert normalize_tool_name("google") == "web_search"

    def test_canonical_and_empty_names(self):
        assert normalize_tool_name("read_file") == "read_file"
        assert normalize_tool_name("terminal") == "terminal"
        assert normalize_tool_name("") == ""
        assert normalize_tool_name("BASH") == "terminal"


class TestToolArgumentsParsing:
    def test_dict_arguments(self):
        args = {"path": "test.txt", "content": "hello"}
        assert parse_tool_arguments(args) == args

    def test_none_arguments(self):
        assert parse_tool_arguments(None) == {}

    def test_json_string_arguments(self):
        raw = json.dumps({"command": "ls -la", "timeout": 30})
        assert parse_tool_arguments(raw) == {"command": "ls -la", "timeout": 30}

    def test_fallback_string_arguments(self):
        assert parse_tool_arguments("ls -la") == {"command": "ls -la"}

    def test_groq_tool_use_failed_dict(self):
        raw = {"tool_use_failed": {"command": "git status"}}
        assert parse_tool_arguments(raw) == {"command": "git status"}

    def test_groq_tool_use_failed_json_string(self):
        raw = {"tool_use_failed": json.dumps({"command": "echo 42"})}
        assert parse_tool_arguments(raw) == {"command": "echo 42"}


class TestUseToolExecution:
    def test_empty_tool_name_returns_error(self):
        res = json.loads(use_tool(""))
        assert "error" in res

    def test_recursive_use_tool_blocked(self):
        res = json.loads(use_tool("use_tool", {"name": "use_tool"}))
        assert "error" in res
        assert "Recursive" in res["error"]

    def test_dispatch_with_mocked_model_tools(self):
        with patch("model_tools.handle_function_call", return_value="mocked_output") as mock_call:
            res = use_tool("bash", '{"command": "echo 123"}', task_id="t1")
            assert res == "mocked_output"
            mock_call.assert_called_once_with(
                function_name="terminal",
                function_args={"command": "echo 123"},
                task_id="t1",
            )

    def test_dispatch_exception_handled(self):
        with patch("model_tools.handle_function_call", side_effect=RuntimeError("something went wrong")):
            res = json.loads(use_tool("terminal", {"command": "bad"}))
            assert "error" in res
            assert "RuntimeError" in res["error"]


class TestCapabilityMapBuilder:
    def test_build_capability_map_structure(self):
        cap_map = build_capability_map()
        assert "total" in cap_map
        assert "categories" in cap_map
        assert "aliases" in cap_map
        assert cap_map["total"] > 0
        assert isinstance(cap_map["categories"], dict)
        assert "terminal" in cap_map["aliases"] or "bash" in cap_map["aliases"]

        # Check a known category
        for cat_name, cat_data in cap_map["categories"].items():
            assert "count" in cat_data
            assert "tools" in cat_data
            assert cat_data["count"] == len(cat_data["tools"])
            for t in cat_data["tools"]:
                assert "name" in t
                assert "description" in t
                assert t["name"] != "use_tool"


class TestBridgeCapabilityMapRPC:
    def test_bridge_skills_map_rpc(self, tmp_path):
        server = BridgeServer(store_path=str(tmp_path / "bridge.db"), fake_model=True)
        conn = MagicMock()
        conn.authenticated = True

        res = server._m_skills_map(conn, {})
        assert "total" in res
        assert "categories" in res
        assert isinstance(res["categories"], dict)

    def test_bridge_capabilities_map_rpc(self, tmp_path):
        server = BridgeServer(store_path=str(tmp_path / "bridge.db"), fake_model=True)
        conn = MagicMock()
        conn.authenticated = True

        res = server._m_capabilities_map(conn, {})
        assert "tools" in res
        assert "skills" in res
        assert "total" in res["tools"]
        assert "categories" in res["tools"]
        assert "total" in res["skills"]
        assert "categories" in res["skills"]

    def test_bridge_capabilities_includes_map_methods(self, tmp_path):
        server = BridgeServer(store_path=str(tmp_path / "bridge.db"), fake_model=True)
        conn = MagicMock()
        conn.authenticated = True

        res = server._m_capabilities(conn, {})
        methods = res.get("methods", [])
        assert "skills.map" in methods
        assert "capabilities.map" in methods


class TestToolsetRegistration:
    def test_capability_map_toolset_exists(self):
        assert "capability_map" in TOOLSETS
        toolset_data = get_toolset("capability_map")
        assert toolset_data is not None
        assert toolset_data["tools"] == ["use_tool"]
        from toolsets import resolve_toolset
        assert resolve_toolset("capability_map") == ["use_tool"]

    def test_use_tool_registered_in_registry(self):
        entry = registry.get_entry("use_tool")
        assert entry is not None
        assert entry.name == "use_tool"
        assert entry.toolset == "capability_map"

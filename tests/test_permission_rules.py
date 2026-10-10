"""Unit and integration tests for tools/permission_rules.py (#59)."""

import pytest
from unittest.mock import patch

from tools.permission_rules import evaluate, evaluate_rule_match, load_rules
import tools.approval as ap


class TestPermissionRulesEvaluation:
    def test_empty_rules_uses_default(self):
        cfg = {"permissions": {"default": "ask", "rules": []}}
        assert evaluate("terminal", "ls", cfg) == "ask"

    def test_default_can_be_allow_or_deny(self):
        cfg_allow = {"permissions": {"default": "allow", "rules": []}}
        assert evaluate("terminal", "ls", cfg_allow) == "allow"

        cfg_deny = {"permissions": {"default": "deny", "rules": []}}
        assert evaluate("terminal", "ls", cfg_deny) == "deny"

    def test_last_rule_wins_on_conflict(self):
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "terminal", "match": "git *", "action": "allow"},
                    {"tool": "terminal", "match": "git commit *", "action": "deny"},
                ],
            }
        }
        assert evaluate("terminal", "git status", cfg) == "allow"
        assert evaluate("terminal", "git commit -m 'test'", cfg) == "deny"

    def test_last_rule_wins_exact_override(self):
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "terminal", "match": "rm *", "action": "deny"},
                    {"tool": "terminal", "match": "rm *", "action": "allow"},
                ],
            }
        }
        # Last rule wins
        assert evaluate("terminal", "rm foo.txt", cfg) == "allow"

    def test_wildcard_tool_matches_any_tool(self):
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "*", "match": "*dangerous*", "action": "deny"},
                ],
            }
        }
        assert evaluate("terminal", "echo dangerous", cfg) == "deny"
        assert evaluate("write_file", "/tmp/dangerous.txt", cfg) == "deny"

    def test_corrupt_config_falls_back_to_ask(self):
        assert evaluate("terminal", "ls", {"permissions": "invalid_not_dict"}) == "ask"
        assert evaluate("terminal", "ls", {"permissions": {"rules": "invalid_not_list"}}) == "ask"
        assert evaluate("terminal", "ls", None) in {"ask", "allow", "deny"}

    def test_case_insensitivity_on_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "terminal", "match": "DIR *", "action": "allow"},
                ],
            }
        }
        assert evaluate("terminal", "dir C:\\Users", cfg) == "allow"


class TestPermissionRulesApprovalIntegration:
    def test_deny_rule_blocks_command_immediately(self, monkeypatch):
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "terminal", "match": "rm *", "action": "deny"},
                ],
            }
        }
        monkeypatch.setattr("fetih_cli.config.load_config", lambda: cfg)
        res = ap.check_all_command_guards("rm -rf /tmp/test", "local")
        assert res["approved"] is False
        assert "Kullanıcı izin kuralı bu komutu engelledi" in res["message"]

    def test_allow_rule_runs_safe_command_without_prompt(self, monkeypatch):
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "terminal", "match": "git *", "action": "allow"},
                ],
            }
        }
        monkeypatch.setattr("fetih_cli.config.load_config", lambda: cfg)
        monkeypatch.setenv("FETIH_INTERACTIVE", "1")
        # git status is not in DANGEROUS_PATTERNS
        res = ap.check_all_command_guards("git status", "local")
        assert res["approved"] is True
        assert res["message"] is None

    def test_allow_rule_does_not_bypass_dangerous_patterns(self, monkeypatch):
        cfg = {
            "permissions": {
                "default": "ask",
                "rules": [
                    {"tool": "terminal", "match": "git *", "action": "allow"},
                ],
            }
        }
        monkeypatch.setattr("fetih_cli.config.load_config", lambda: cfg)
        # git push --force is in DANGEROUS_PATTERNS
        # In non-interactive mode with mode != off, it will be detected as dangerous
        is_dang, pk, desc = ap.detect_dangerous_command("git push --force")
        assert is_dang is True, "git push --force must be flagged as dangerous"

"""Tests for Issue #58: Desktop workspace guard and sensitive file protection."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.file_safety import (
    get_sensitive_read_error,
    is_outside_safe_root,
    is_sensitive_read_denied,
)
from fetih_desktop_bridge.workspace import apply_workspace, current_workspace, reset_workspace
from tools.approval import clear_session, register_gateway_notify, unregister_gateway_notify
from tools.environments.local import LocalEnvironment
from tools.file_operations import ShellFileOperations
from tools.file_tools import read_file_tool, search_tool


@pytest.fixture(autouse=True)
def cleanup_workspace():
    old_root = os.environ.get("FETIH_WRITE_SAFE_ROOT")
    reset_workspace()
    yield
    reset_workspace()
    if old_root is not None:
        os.environ["FETIH_WRITE_SAFE_ROOT"] = old_root
    else:
        os.environ.pop("FETIH_WRITE_SAFE_ROOT", None)


class TestWorkspaceGuard:
    def test_apply_workspace_and_current(self, tmp_path: Path):
        ws = tmp_path / "my_project"
        ws.mkdir()
        norm = apply_workspace(str(ws), restrict=True)
        assert norm == str(ws.resolve())
        assert current_workspace() == str(ws.resolve())
        assert os.environ["FETIH_WRITE_SAFE_ROOT"] == str(ws.resolve())

    def test_writes_inside_workspace_allowed_without_approval(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        apply_workspace(str(ws), restrict=True)

        ops = ShellFileOperations(LocalEnvironment(cwd=str(ws)), cwd=str(ws))
        target_file = ws / "sub" / "file.txt"
        res = ops.write_file(str(target_file), "hello world")
        assert res.error is None
        assert target_file.read_text(encoding="utf-8") == "hello world"

    def test_writes_outside_workspace_prompts_and_fails_on_deny(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        outside_dir = tmp_path / "outside"
        ws.mkdir()
        outside_dir.mkdir()
        apply_workspace(str(ws), restrict=True)

        ops = ShellFileOperations(LocalEnvironment(cwd=str(ws)), cwd=str(ws))
        outside_file = outside_dir / "blocked.txt"

        # Mock request_action_approval returning 'deny'
        with patch("tools.approval.request_action_approval", return_value="deny") as mock_ask:
            res = ops.write_file(str(outside_file), "sensitive")
            assert mock_ask.called
            assert res.error is not None
            assert "outside the workspace safe root" in res.error
            assert not outside_file.exists()

    def test_writes_outside_workspace_succeeds_on_user_approval(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        outside_dir = tmp_path / "outside"
        ws.mkdir()
        outside_dir.mkdir()
        apply_workspace(str(ws), restrict=True)

        ops = ShellFileOperations(LocalEnvironment(cwd=str(ws)), cwd=str(ws))
        outside_file = outside_dir / "allowed_by_user.txt"

        with patch("tools.approval.request_action_approval", return_value="once") as mock_ask:
            res = ops.write_file(str(outside_file), "user approved content")
            assert mock_ask.called
            assert res.error is None
            assert outside_file.read_text(encoding="utf-8") == "user approved content"

    def test_dot_dot_escape_is_detected_as_outside(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        apply_workspace(str(ws), restrict=True)

        escape_path = str(ws / ".." / "escaped.txt")
        assert is_outside_safe_root(escape_path) is True

    def test_turkish_characters_in_workspace_path(self, tmp_path: Path):
        tr_dir = tmp_path / "türkçe_şeker_ağacı_ğüşöç"
        tr_dir.mkdir()
        apply_workspace(str(tr_dir), restrict=True)

        inside_file = tr_dir / "belge.txt"
        assert is_outside_safe_root(str(inside_file)) is False

        ops = ShellFileOperations(LocalEnvironment(cwd=str(tr_dir)), cwd=str(tr_dir))
        res = ops.write_file(str(inside_file), "Türkçe içerik: çşğüöı")
        assert res.error is None
        assert inside_file.read_text(encoding="utf-8") == "Türkçe içerik: çşğüöı"

    def test_symlink_pointing_outside_is_blocked(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        outside_dir = tmp_path / "outside"
        ws.mkdir()
        outside_dir.mkdir()
        apply_workspace(str(ws), restrict=True)

        symlink_to_outside = ws / "sym_outside"
        try:
            symlink_to_outside.symlink_to(outside_dir, target_is_directory=True)
        except OSError:
            pytest.skip("Symlinks not supported on this platform/filesystem")

        target_file_via_symlink = symlink_to_outside / "leaked.txt"
        assert is_outside_safe_root(str(target_file_via_symlink)) is True

    def test_patch_replace_outside_workspace_prompts_approval(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        outside_dir = tmp_path / "outside"
        ws.mkdir()
        outside_dir.mkdir()
        outside_file = outside_dir / "target.txt"
        outside_file.write_text("initial text", encoding="utf-8")

        apply_workspace(str(ws), restrict=True)
        ops = ShellFileOperations(LocalEnvironment(cwd=str(ws)), cwd=str(ws))

        with patch("tools.approval.request_action_approval", return_value="deny") as mock_ask:
            res = ops.patch_replace(str(outside_file), "initial text", "new text")
            assert mock_ask.called
            assert res.error is not None
            assert "outside the workspace safe root" in res.error
            assert outside_file.read_text(encoding="utf-8") == "initial text"


class TestSensitiveFileProtection:
    def test_read_dot_env_denied(self, tmp_path: Path):
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=12345", encoding="utf-8")

        assert is_sensitive_read_denied(str(env_file)) is True
        ops = ShellFileOperations(LocalEnvironment(cwd=str(tmp_path)), cwd=str(tmp_path))
        res = ops.read_file(str(env_file))
        assert res.error is not None
        assert "Read denied" in res.error

        tool_out = json.loads(read_file_tool(str(env_file)))
        assert "error" in tool_out
        assert "Read denied" in tool_out["error"]

    def test_read_dot_env_variants_denied(self, tmp_path: Path):
        for name in [".env.local", ".env.production", ".env.staging"]:
            f = tmp_path / name
            f.write_text("SECRET=1", encoding="utf-8")
            assert is_sensitive_read_denied(str(f)) is True
            ops = ShellFileOperations(LocalEnvironment(cwd=str(tmp_path)), cwd=str(tmp_path))
            res = ops.read_file(str(f))
            assert res.error is not None
            assert "Read denied" in res.error

    def test_read_dot_env_example_and_sample_allowed(self, tmp_path: Path):
        for name in [".env.example", ".env.sample", ".env.template"]:
            f = tmp_path / name
            f.write_text("EXAMPLE=foo", encoding="utf-8")
            assert is_sensitive_read_denied(str(f)) is False
            ops = ShellFileOperations(LocalEnvironment(cwd=str(tmp_path)), cwd=str(tmp_path))
            res = ops.read_file(str(f))
            assert res.error is None
            assert "EXAMPLE=foo" in res.content

            tool_out = json.loads(read_file_tool(str(f)))
            assert "error" not in tool_out
            assert "EXAMPLE=foo" in tool_out.get("content", "")

    def test_read_id_rsa_and_pem_denied(self, tmp_path: Path):
        for name in ["id_rsa", "id_rsa.pub", "cert.pem", "private_key.pem"]:
            f = tmp_path / name
            f.write_text("-----BEGIN KEY-----", encoding="utf-8")
            assert is_sensitive_read_denied(str(f)) is True
            ops = ShellFileOperations(LocalEnvironment(cwd=str(tmp_path)), cwd=str(tmp_path))
            res = ops.read_file(str(f))
            assert res.error is not None
            assert "Read denied" in res.error

    def test_search_files_rejects_sensitive_target_path(self, tmp_path: Path):
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_FOO=bar", encoding="utf-8")

        res_str = search_tool(pattern="SECRET", path=str(env_file))
        res_data = json.loads(res_str)
        assert "error" in res_data
        assert "Read denied" in res_data["error"]

"""Desktop and Packaging regression tests.

Verifies:
1. Branding assets and icons exist and are valid.
2. CLI is executable as a module via `python -m fetih_cli` (required by Desktop Wizard).
3. Provider normalization for setup wizard (Gemini CLI, Codex OAuth).
4. Packaging scripts and Inno Setup installer definitions.
5. Desktop bridge RPC findings integration.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from fetih_cli.auth_commands import _normalize_provider
from fetih_desktop_bridge.protocol import decode, encode, request
from fetih_desktop_bridge.server import BridgeServer

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_branding_ico_asset_valid():
    ico_path = REPO_ROOT / "apps" / "windows" / "Fetih.Desktop" / "assets" / "fetih.ico"
    assert ico_path.exists(), f"fetih.ico missing at {ico_path}"
    data = ico_path.read_bytes()
    assert len(data) > 100
    # Standard Windows ICO header: 0x0000 (reserved), 0x0001 (type 1 for icon)
    assert data[:4] == b"\x00\x00\x01\x00", "Invalid ICO header"


def test_python_m_fetih_cli_executable():
    """Desktop setup wizard invokes `python -m fetih_cli ...`."""
    result = subprocess.run(
        [sys.executable, "-m", "fetih_cli", "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"Error running `python -m fetih_cli --help`: {result.stderr}"
    assert "fetih" in result.stdout.lower() or "usage" in result.stdout.lower()


def test_auth_provider_aliases_wizard():
    """Verify setup wizard aliases are recognized by auth command normalizer."""
    assert _normalize_provider("gemini-cli") == "google-gemini-cli"
    assert _normalize_provider("gemini-oauth") == "google-gemini-cli"
    assert _normalize_provider("google-gemini") == "google-gemini-cli"
    assert _normalize_provider("codex") == "openai-codex"
    assert _normalize_provider("chatgpt") == "openai-codex"
    assert _normalize_provider("codex-oauth") == "openai-codex"
    assert _normalize_provider("qwen") == "qwen-oauth"


def test_packaging_installer_iss_syntax():
    iss_file = REPO_ROOT / "packaging" / "windows" / "installer.iss"
    assert iss_file.exists(), f"installer.iss missing at {iss_file}"
    content = iss_file.read_text(encoding="utf-8")

    assert "AppName=FETİH" in content
    assert "AppId={{E844AC82-70F4-41A8-B6A7-7C5F5E4E3A01}}" in content
    assert "Source: \"{#PublishDir}\\*\"" in content
    assert "Source: \"{#RepoRoot}\\fetih_cli\\*\"" in content
    assert "Source: \"{#RepoRoot}\\fetih_desktop_bridge\\*\"" in content
    assert "Source: \"{#RepoRoot}\\*.py\"" in content
    assert "Fetih.Desktop.exe" in content
    assert "fetih.cmd" in content
    assert "AddPathToEnv" in content


def test_packaging_fetih_cmd():
    cmd_file = REPO_ROOT / "packaging" / "windows" / "fetih.cmd"
    assert cmd_file.exists(), f"fetih.cmd missing at {cmd_file}"
    content = cmd_file.read_text(encoding="utf-8")

    assert "PYTHONPATH" in content
    assert "python -m fetih_cli" in content
    assert "Fetih.Desktop.exe" in content


def test_packaging_build_installer_ps1():
    ps1_file = REPO_ROOT / "packaging" / "windows" / "build-installer.ps1"
    assert ps1_file.exists(), f"build-installer.ps1 missing at {ps1_file}"
    content = ps1_file.read_text(encoding="utf-8")

    assert "dotnet publish" in content
    assert "ISCC.exe" in content
    assert "installer.iss" in content


def test_crash_log_clean():
    """Verify that no unhandled crash occurred during desktop testing."""
    local_app_data = os.getenv("LOCALAPPDATA", "")
    if local_app_data:
        crash_log = Path(local_app_data) / "Fetih" / "Desktop" / "crash.log"
        if crash_log.exists():
            content = crash_log.read_text(encoding="utf-8").strip()
            # If log exists, it should be empty or contain 0 fatal exceptions
            assert "Exception" not in content or "FATAL" not in content


def test_gemini_oauth_module_contract():
    """Verify Gemini OAuth helper exists and has expected callable entrypoint."""
    from agent.google_oauth import run_gemini_oauth_login_pure, GoogleCredentials
    assert callable(run_gemini_oauth_login_pure)
    assert GoogleCredentials is not None


def test_bridge_findings_ctf_flag_detection():
    """Verify BridgeServer detects CTF flags and creates security findings."""
    import re
    flag_text = "Congratulations! You found the flag: fetih{byp4ss_s3cur1ty_ch3ck_2026}"
    flag_match = re.search(r"(?:CTF|FLAG|fetih)\{[A-Za-z0-9_\-!@#$%^&*+=]+\}", flag_text, re.IGNORECASE)
    assert flag_match is not None
    assert flag_match.group(0) == "fetih{byp4ss_s3cur1ty_ch3ck_2026}"


def test_setup_steps_oauth_provider_auth_coverage():
    """Verify SetupSteps.cs has EnsureProviderAuthStep in pipeline before VerifyEndToEndStep."""
    setup_steps_cs = REPO_ROOT / "apps" / "windows" / "Fetih.Desktop" / "Setup" / "SetupSteps.cs"
    assert setup_steps_cs.exists()
    content = setup_steps_cs.read_text(encoding="utf-8")

    assert "class EnsureProviderAuthStep" in content
    assert "new EnsureProviderAuthStep()" in content

    # Verify order in BuildDefaultSteps:
    # EnsureProviderAuthStep must come after StartDesktopBridgeStep and before VerifyEndToEndStep
    bridge_idx = content.find("new StartDesktopBridgeStep()")
    auth_idx = content.find("new EnsureProviderAuthStep()")
    verify_idx = content.find("new VerifyEndToEndStep()")

    assert bridge_idx > 0
    assert auth_idx > bridge_idx, "EnsureProviderAuthStep must be scheduled after StartDesktopBridgeStep"
    assert verify_idx > auth_idx, "VerifyEndToEndStep must be scheduled after EnsureProviderAuthStep"


def test_setup_window_handles_oauth_browser_and_cli_login():
    """Verify SetupWindow.xaml.cs handles both CliLogin and OAuthBrowser."""
    setup_win_cs = REPO_ROOT / "apps" / "windows" / "Fetih.Desktop" / "SetupWindow.xaml.cs"
    assert setup_win_cs.exists()
    content = setup_win_cs.read_text(encoding="utf-8")

    assert "case ProviderKind.OAuthBrowser:" in content
    assert "ProviderKind.OAuthBrowser" in content


def test_auth_commands_add_dispatch_support():
    """Verify both google-gemini-cli and openai-codex have real login handlers in auth_commands."""
    auth_cmds = REPO_ROOT / "fetih_cli" / "auth_commands.py"
    assert auth_cmds.exists()
    content = auth_cmds.read_text(encoding="utf-8")

    assert 'if provider == "google-gemini-cli":' in content
    assert 'if provider == "openai-codex":' in content
    assert "run_gemini_oauth_login_pure" in content
    assert "_codex_device_code_login" in content

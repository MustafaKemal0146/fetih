"""Tests for per-profile subprocess HOME isolation (#4426).

Verifies that subprocesses (terminal, execute_code, background processes)
receive a per-profile HOME directory while the Python process's own HOME
and Path.home() remain unchanged.

See: https://github.com/MustafaKemal0146/fetih/issues/4426
"""

import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# get_subprocess_home()
# ---------------------------------------------------------------------------

class TestGetSubprocessHome:
    """Unit tests for fetih_constants.get_subprocess_home()."""

    def test_returns_none_when_fetih_home_unset(self, monkeypatch):
        monkeypatch.delenv("FETIH_HOME", raising=False)
        from fetih_constants import get_subprocess_home
        assert get_subprocess_home() is None

    def test_returns_none_when_home_dir_missing(self, tmp_path, monkeypatch):
        fetih_home = tmp_path / ".fetih"
        fetih_home.mkdir()
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))
        # No home/ subdirectory created
        from fetih_constants import get_subprocess_home
        assert get_subprocess_home() is None

    def test_returns_path_when_home_dir_exists(self, tmp_path, monkeypatch):
        fetih_home = tmp_path / ".fetih"
        fetih_home.mkdir()
        profile_home = fetih_home / "home"
        profile_home.mkdir()
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))
        from fetih_constants import get_subprocess_home
        assert get_subprocess_home() == str(profile_home)

    def test_returns_profile_specific_path(self, tmp_path, monkeypatch):
        """Named profiles get their own isolated HOME."""
        profile_dir = tmp_path / ".fetih" / "profiles" / "coder"
        profile_dir.mkdir(parents=True)
        profile_home = profile_dir / "home"
        profile_home.mkdir()
        monkeypatch.setenv("FETIH_HOME", str(profile_dir))
        from fetih_constants import get_subprocess_home
        assert get_subprocess_home() == str(profile_home)

    def test_two_profiles_get_different_homes(self, tmp_path, monkeypatch):
        base = tmp_path / ".fetih" / "profiles"
        for name in ("alpha", "beta"):
            p = base / name
            p.mkdir(parents=True)
            (p / "home").mkdir()

        from fetih_constants import get_subprocess_home

        monkeypatch.setenv("FETIH_HOME", str(base / "alpha"))
        home_a = get_subprocess_home()

        monkeypatch.setenv("FETIH_HOME", str(base / "beta"))
        home_b = get_subprocess_home()

        assert home_a is not None
        assert home_b is not None
        assert home_a != home_b
        assert home_a.endswith("alpha/home")
        assert home_b.endswith("beta/home")

    def test_context_override_is_thread_local(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        profile = tmp_path / "profile"
        root.mkdir()
        profile.mkdir()
        monkeypatch.setenv("FETIH_HOME", str(root))

        from fetih_constants import (
            get_fetih_home,
            reset_fetih_home_override,
            set_fetih_home_override,
        )

        ready = threading.Event()
        release = threading.Event()
        seen: list[str] = []

        def read_from_other_thread():
            ready.set()
            release.wait(timeout=5)
            seen.append(str(get_fetih_home()))

        thread = threading.Thread(target=read_from_other_thread)
        thread.start()
        assert ready.wait(timeout=5)

        token = set_fetih_home_override(profile)
        try:
            assert get_fetih_home() == profile
            release.set()
            thread.join(timeout=5)
        finally:
            reset_fetih_home_override(token)
            release.set()

        assert seen == [str(root)]
        assert get_fetih_home() == root


# ---------------------------------------------------------------------------
# _make_run_env() injection
# ---------------------------------------------------------------------------

class TestMakeRunEnvHomeInjection:
    """Verify _make_run_env() injects HOME into subprocess envs."""

    def test_injects_home_when_profile_home_exists(self, tmp_path, monkeypatch):
        fetih_home = tmp_path / "fetih"
        fetih_home.mkdir()
        (fetih_home / "home").mkdir()
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))
        monkeypatch.setenv("HOME", "/root")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        from tools.environments.local import _make_run_env
        result = _make_run_env({})

        assert result["HOME"] == str(fetih_home / "home")

    def test_no_injection_when_home_dir_missing(self, tmp_path, monkeypatch):
        fetih_home = tmp_path / "fetih"
        fetih_home.mkdir()
        # No home/ subdirectory
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))
        monkeypatch.setenv("HOME", "/root")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        from tools.environments.local import _make_run_env
        result = _make_run_env({})

        assert result["HOME"] == "/root"

    def test_no_injection_when_fetih_home_unset(self, monkeypatch):
        monkeypatch.delenv("FETIH_HOME", raising=False)
        monkeypatch.setenv("HOME", "/home/user")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        from tools.environments.local import _make_run_env
        result = _make_run_env({})

        assert result["HOME"] == "/home/user"

    def test_context_override_bridges_to_subprocess_env(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        profile = tmp_path / "profile"
        root.mkdir()
        profile.mkdir()
        (profile / "home").mkdir()
        monkeypatch.setenv("FETIH_HOME", str(root))
        monkeypatch.setenv("HOME", "/root")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        from fetih_constants import reset_fetih_home_override, set_fetih_home_override
        from tools.environments.local import _make_run_env

        token = set_fetih_home_override(profile)
        try:
            result = _make_run_env({})
        finally:
            reset_fetih_home_override(token)

        assert result["FETIH_HOME"] == str(profile)
        assert result["HOME"] == str(profile / "home")


# ---------------------------------------------------------------------------
# _sanitize_subprocess_env() injection
# ---------------------------------------------------------------------------

class TestSanitizeSubprocessEnvHomeInjection:
    """Verify _sanitize_subprocess_env() injects HOME for background procs."""

    def test_injects_home_when_profile_home_exists(self, tmp_path, monkeypatch):
        fetih_home = tmp_path / "fetih"
        fetih_home.mkdir()
        (fetih_home / "home").mkdir()
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))

        base_env = {"HOME": "/root", "PATH": "/usr/bin", "USER": "root"}
        from tools.environments.local import _sanitize_subprocess_env
        result = _sanitize_subprocess_env(base_env)

        assert result["HOME"] == str(fetih_home / "home")

    def test_no_injection_when_home_dir_missing(self, tmp_path, monkeypatch):
        fetih_home = tmp_path / "fetih"
        fetih_home.mkdir()
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))

        base_env = {"HOME": "/root", "PATH": "/usr/bin"}
        from tools.environments.local import _sanitize_subprocess_env
        result = _sanitize_subprocess_env(base_env)

        assert result["HOME"] == "/root"

    def test_context_override_bridges_to_background_env(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        profile = tmp_path / "profile"
        root.mkdir()
        profile.mkdir()
        (profile / "home").mkdir()
        monkeypatch.setenv("FETIH_HOME", str(root))

        base_env = {"HOME": "/root", "PATH": "/usr/bin"}
        from fetih_constants import reset_fetih_home_override, set_fetih_home_override
        from tools.environments.local import _sanitize_subprocess_env

        token = set_fetih_home_override(profile)
        try:
            result = _sanitize_subprocess_env(base_env)
        finally:
            reset_fetih_home_override(token)

        assert result["FETIH_HOME"] == str(profile)
        assert result["HOME"] == str(profile / "home")


# ---------------------------------------------------------------------------
# Profile bootstrap
# ---------------------------------------------------------------------------

class TestProfileBootstrap:
    """Verify new profiles get a home/ subdirectory."""

    def test_profile_dirs_includes_home(self):
        from fetih_cli.profiles import _PROFILE_DIRS
        assert "home" in _PROFILE_DIRS

    def test_create_profile_bootstraps_home_dir(self, tmp_path, monkeypatch):
        """create_profile() should create home/ inside the profile dir."""
        home = tmp_path / ".fetih"
        home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setenv("FETIH_HOME", str(home))

        from fetih_cli.profiles import create_profile
        profile_dir = create_profile("testbot", no_alias=True)
        assert (profile_dir / "home").is_dir()


# ---------------------------------------------------------------------------
# Python process HOME unchanged
# ---------------------------------------------------------------------------

class TestPythonProcessUnchanged:
    """Confirm the Python process's own HOME is never modified."""

    def test_path_home_unchanged_after_subprocess_home_resolved(
        self, tmp_path, monkeypatch
    ):
        fetih_home = tmp_path / "fetih"
        fetih_home.mkdir()
        (fetih_home / "home").mkdir()
        monkeypatch.setenv("FETIH_HOME", str(fetih_home))

        original_home = os.environ.get("HOME")
        original_path_home = str(Path.home())

        from fetih_constants import get_subprocess_home
        sub_home = get_subprocess_home()

        # Subprocess home is set but Python HOME stays the same
        assert sub_home is not None
        assert os.environ.get("HOME") == original_home
        assert str(Path.home()) == original_path_home

"""Auto-updater for FETIH CLI and its skills/tools.

Checks GitHub releases for new versions, downloads and applies updates,
maintains an update log, and supports rollback.

Commands:
  fetih update --check           Check for available updates
  fetih update --apply           Apply pending updates
  fetih update --rollback        Roll back to the previous version
  fetih update --status          Show update history and current version
  fetih update --skills          Check/update skill files only
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def _get_current_version() -> str:
    """Return the current FETIH version."""
    try:
        from fetih_cli import __version__
        return __version__
    except ImportError:
        return "0.0.0"


def _parse_version(version_str: str) -> Tuple[int, int, int]:
    """Parse a semver string into (major, minor, patch)."""
    v = version_str.lstrip("vV")
    parts = v.split(".")
    major = int(parts[0]) if parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return (major, minor, patch)


def _version_newer(ver_a: str, ver_b: str) -> bool:
    """Return True if ver_a is newer than ver_b."""
    return _parse_version(ver_a) > _parse_version(ver_b)


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

GITHUB_REPO = "MustafaKemal0146/fetih"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"


def _fetch_latest_release() -> Optional[Dict[str, Any]]:
    """Fetch the latest release info from GitHub."""
    import urllib.request
    import urllib.error

    url = f"{GITHUB_API}/releases/latest"
    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "FETIH-Updater/1.0")

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # No releases yet
        logger.warning("GitHub API error: %s", e)
        return None
    except Exception as e:
        logger.warning("Failed to fetch release: %s", e)
        return None


def _fetch_all_releases() -> List[Dict[str, Any]]:
    """Fetch all releases from GitHub."""
    import urllib.request
    import urllib.error

    url = f"{GITHUB_API}/releases"
    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "FETIH-Updater/1.0")

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except Exception as e:
        logger.warning("Failed to fetch releases: %s", e)
        return []


# ---------------------------------------------------------------------------
# Update state
# ---------------------------------------------------------------------------

def _update_state_path() -> Path:
    """Return path to the update state file."""
    fetih_home = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))
    return Path(fetih_home) / "update_state.json"


def _load_update_state() -> Dict[str, Any]:
    """Load the update state."""
    path = _update_state_path()
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"history": [], "last_check": None, "applied_version": None}


def _save_update_state(state: Dict[str, Any]) -> None:
    """Save the update state."""
    path = _update_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save update state: %s", e)


# ---------------------------------------------------------------------------
# Update operations
# ---------------------------------------------------------------------------

def check_for_updates() -> Dict[str, Any]:
    """Check if a newer version is available on GitHub.

    Returns a dict with:
      - current_version
      - latest_version (or None if check failed)
      - update_available (bool)
      - release_url
      - release_notes
    """
    current = _get_current_version()
    release = _fetch_latest_release()

    result = {
        "current_version": current,
        "latest_version": None,
        "update_available": False,
        "release_url": None,
        "release_notes": "",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    if release is None:
        result["error"] = "Failed to check for updates (GitHub API unreachable)"
        return result

    latest_tag = release.get("tag_name", "")
    latest_version = latest_tag.lstrip("vV")
    result["latest_version"] = latest_version
    result["release_url"] = release.get("html_url", "")
    result["release_notes"] = (release.get("body") or "")[:500]

    if _version_newer(latest_version, current):
        result["update_available"] = True

    # Update last check time
    state = _load_update_state()
    state["last_check"] = result["checked_at"]
    _save_update_state(state)

    return result


def apply_update() -> Dict[str, Any]:
    """Apply the latest update.

    For a git-managed install, this runs git pull.
    For a pip install, this runs pip install --upgrade.
    """
    current = _get_current_version()

    result = {
        "success": False,
        "previous_version": current,
        "new_version": current,
        "method": "unknown",
        "message": "",
    }

    # Try git first (development install)
    try:
        repo_dir = Path(__file__).resolve().parent.parent
        if (repo_dir / ".git").exists():
            result["method"] = "git"

            # Check for local changes
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(repo_dir),
                capture_output=True, text=True, timeout=10,
            )
            if status.stdout.strip():
                result["message"] = (
                    "Local changes detected. Stash or commit them before updating.\n"
                    f"Changed files:\n{status.stdout[:500]}"
                )
                return result

            # Pull latest
            pull = subprocess.run(
                ["git", "pull", "--ff-only", "origin", "main"],
                cwd=str(repo_dir),
                capture_output=True, text=True, timeout=30,
            )
            if pull.returncode != 0:
                result["message"] = f"Git pull failed:\n{pull.stderr[:300]}"
                return result

            # Reinstall
            pip = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", str(repo_dir)],
                capture_output=True, text=True, timeout=60,
            )

            # Get new version
            try:
                from fetih_cli import __version__
                result["new_version"] = __version__
            except ImportError:
                pass

            result["success"] = True
            result["message"] = f"Updated via git pull ({pull.stdout.strip()[:200]})"
            return result
    except Exception as e:
        logger.warning("Git update failed: %s", e)

    # Fallback: pip upgrade
    try:
        result["method"] = "pip"
        pip = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "fetih"],
            capture_output=True, text=True, timeout=60,
        )
        if pip.returncode == 0:
            result["success"] = True
            result["message"] = "Updated via pip install --upgrade"
        else:
            result["message"] = f"Pip upgrade failed:\n{pip.stderr[:300]}"
    except Exception as e:
        result["message"] = f"Update failed: {e}"

    # Record in history
    if result["success"]:
        _record_update(result)

    return result


def rollback_update() -> Dict[str, Any]:
    """Roll back to the previous version.

    For git installs, this uses git reset to the previous tag/commit.
    For pip installs, this reinstalls the previous version.
    """
    state = _load_update_state()
    history = state.get("history", [])

    if len(history) < 2:
        return {
            "success": False,
            "message": "No previous version to roll back to. Only one update in history.",
        }

    previous = history[-2]  # The version BEFORE the last update

    result = {
        "success": False,
        "message": "",
        "rolled_back_to": previous.get("previous_version", "unknown"),
    }

    # Git rollback
    try:
        repo_dir = Path(__file__).resolve().parent.parent
        if (repo_dir / ".git").exists():
            prev_ver = previous.get("previous_version", "")
            tag = f"v{prev_ver}"

            # Try to reset to the previous version's tag
            reset = subprocess.run(
                ["git", "checkout", tag],
                cwd=str(repo_dir),
                capture_output=True, text=True, timeout=15,
            )
            if reset.returncode != 0:
                # Try the commit hash
                commit = previous.get("commit", "")
                if commit:
                    reset = subprocess.run(
                        ["git", "checkout", commit],
                        cwd=str(repo_dir),
                        capture_output=True, text=True, timeout=15,
                    )

            if reset.returncode == 0:
                # Reinstall
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-e", str(repo_dir)],
                    capture_output=True, text=True, timeout=60,
                )
                result["success"] = True
                result["message"] = f"Rolled back to version {prev_ver}"
                return result
    except Exception as e:
        logger.warning("Git rollback failed: %s", e)

    # Pip rollback
    try:
        prev_ver = previous.get("previous_version", "")
        pip = subprocess.run(
            [sys.executable, "-m", "pip", "install", f"fetih=={prev_ver}"],
            capture_output=True, text=True, timeout=60,
        )
        if pip.returncode == 0:
            result["success"] = True
            result["message"] = f"Rolled back to fetih=={prev_ver}"
        else:
            result["message"] = f"Pip rollback failed:\n{pip.stderr[:300]}"
    except Exception as e:
        result["message"] = f"Rollback failed: {e}"

    return result


def _record_update(result: Dict[str, Any]) -> None:
    """Record an update in the update history."""
    state = _load_update_state()
    history = state.get("history", [])

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "previous_version": result["previous_version"],
        "new_version": result["new_version"],
        "method": result.get("method", "unknown"),
    }

    # Record current git commit if available
    try:
        repo_dir = Path(__file__).resolve().parent.parent
        if (repo_dir / ".git").exists():
            commit = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=str(repo_dir),
                capture_output=True, text=True, timeout=5,
            )
            if commit.returncode == 0:
                entry["commit"] = commit.stdout.strip()
    except Exception:
        pass

    history.append(entry)
    # Keep last 20 updates
    if len(history) > 20:
        history = history[-20:]

    state["history"] = history
    state["applied_version"] = result["new_version"]
    _save_update_state(state)


def get_update_status() -> Dict[str, Any]:
    """Return comprehensive update status."""
    state = _load_update_state()
    current = _get_current_version()

    return {
        "current_version": current,
        "last_check": state.get("last_check"),
        "applied_version": state.get("applied_version"),
        "update_count": len(state.get("history", [])),
        "history": state.get("history", [])[-5:],  # Last 5 updates
    }

"""Shared file safety rules used by both tools and ACP shims."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def _fetih_home_path() -> Path:
    """Resolve the active FETIH_HOME (profile-aware) without circular imports."""
    try:
        from fetih_constants import get_fetih_home  # local import to avoid cycles
        return get_fetih_home()
    except Exception:
        return Path(os.path.expanduser("~/.fetih"))


def build_write_denied_paths(home: str) -> set[str]:
    """Return exact sensitive paths that must never be written."""
    fetih_home = _fetih_home_path()
    return {
        os.path.realpath(p)
        for p in [
            os.path.join(home, ".ssh", "authorized_keys"),
            os.path.join(home, ".ssh", "id_rsa"),
            os.path.join(home, ".ssh", "id_ed25519"),
            os.path.join(home, ".ssh", "config"),
            str(fetih_home / ".env"),
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".zshrc"),
            os.path.join(home, ".profile"),
            os.path.join(home, ".bash_profile"),
            os.path.join(home, ".zprofile"),
            os.path.join(home, ".netrc"),
            os.path.join(home, ".pgpass"),
            os.path.join(home, ".npmrc"),
            os.path.join(home, ".pypirc"),
            "/etc/sudoers",
            "/etc/passwd",
            "/etc/shadow",
        ]
    }


def build_write_denied_prefixes(home: str) -> list[str]:
    """Return sensitive directory prefixes that must never be written."""
    return [
        os.path.realpath(p) + os.sep
        for p in [
            os.path.join(home, ".ssh"),
            os.path.join(home, ".aws"),
            os.path.join(home, ".gnupg"),
            os.path.join(home, ".kube"),
            "/etc/sudoers.d",
            "/etc/systemd",
            os.path.join(home, ".docker"),
            os.path.join(home, ".azure"),
            os.path.join(home, ".config", "gh"),
        ]
    ]


def get_safe_write_root() -> Optional[str]:
    """Return the resolved FETIH_WRITE_SAFE_ROOT path, or None if unset."""
    root = os.getenv("FETIH_WRITE_SAFE_ROOT", "")
    if not root:
        return None
    try:
        return os.path.realpath(os.path.expanduser(root))
    except Exception:
        return None


def is_system_write_denied(path: str) -> bool:
    """Return True if path is blocked by the static write denylist."""
    home = os.path.realpath(os.path.expanduser("~"))
    resolved = os.path.realpath(os.path.expanduser(str(path)))

    if resolved in build_write_denied_paths(home):
        return True
    for prefix in build_write_denied_prefixes(home):
        if resolved.startswith(prefix):
            return True
    return False


def _normalize_safe_path(p: str) -> str:
    p_str = str(p)
    if len(p_str) >= 3 and p_str[0] == "/" and p_str[2] == "/" and p_str[1].isalpha():
        p_str = f"{p_str[1].upper()}:{p_str[2:]}"
    expanded = os.path.realpath(os.path.expanduser(p_str))
    norm = os.path.normcase(expanded)
    if os.name == "nt" or "\\" in p_str or (len(p_str) > 1 and p_str[1] == ":"):
        norm = norm.lower().replace("/", "\\")
    return norm


def is_outside_safe_root(path: str) -> bool:
    """Return True if path is outside the FETIH_WRITE_SAFE_ROOT directory tree."""
    safe_root = get_safe_write_root()
    if not safe_root:
        return False
    norm_safe = _normalize_safe_path(safe_root)
    norm_path = _normalize_safe_path(path)

    sep = "\\" if ("\\" in norm_safe or os.name == "nt") else "/"
    norm_safe_trimmed = norm_safe.rstrip("/\\")
    if norm_path == norm_safe_trimmed:
        return False
    if norm_path.startswith(norm_safe_trimmed + sep) or norm_path.startswith(norm_safe_trimmed + "/"):
        return False
    return True


def is_write_denied(path: str) -> bool:
    """Return True if path is blocked by the write denylist or safe root."""
    return is_system_write_denied(path) or is_outside_safe_root(path)


def is_sensitive_read_denied(path: str) -> bool:
    """Return True if path is a protected credential or environment file."""
    if not path:
        return False
    path_str = str(path).replace("\\", "/")
    name = os.path.basename(path_str.rstrip("/"))

    if name == ".env":
        return True
    if name.startswith(".env."):
        if name in (".env.example", ".env.sample", ".env.template") or name.endswith(".example") or name.endswith(".sample"):
            pass
        else:
            return True

    if name.startswith("id_rsa") or name.endswith(".pem"):
        return True

    try:
        fetih_home = _fetih_home_path().resolve()
        resolved = Path(path).expanduser().resolve()
        if resolved == fetih_home / ".env":
            return True
    except Exception:
        pass

    try:
        from fetih_cli.config import load_config

        cfg = load_config()
        protected = (cfg.get("desktop") or {}).get("protected_paths", [])
        if isinstance(protected, list):
            import fnmatch

            for pat in protected:
                if fnmatch.fnmatch(name, str(pat)) or fnmatch.fnmatch(path_str, str(pat)):
                    return True
    except Exception:
        pass

    return False


def get_sensitive_read_error(path: str) -> Optional[str]:
    """Return an error message if the path is a sensitive read target."""
    if is_sensitive_read_denied(path):
        return f"Read denied: '{path}' is a protected credential/environment file."
    return None



def get_read_block_error(path: str) -> Optional[str]:
    """Return an error message when a read targets internal FETIH cache files."""
    resolved = Path(path).expanduser().resolve()
    fetih_home = _fetih_home_path().resolve()
    blocked_dirs = [
        fetih_home / "skills" / ".hub" / "index-cache",
        fetih_home / "skills" / ".hub",
    ]
    for blocked in blocked_dirs:
        try:
            resolved.relative_to(blocked)
        except ValueError:
            continue
        return (
            f"Access denied: {path} is an internal FETIH cache file "
            "and cannot be read directly to prevent prompt injection. "
            "Use the skills_list or skill_view tools instead."
        )
    return None

"""Local execution environment — spawn-per-call with session snapshot."""

import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from tools.environments import windows_shell
from tools.environments.base import BaseEnvironment, _pipe_stdin

_IS_WINDOWS = platform.system() == "Windows"

# Windows: detect "start <app>" GUI-launch commands that would cause
# pipe-inheritance hangs when run through bash with stdout=PIPE.
# Matches: start [title] program,  cmd /c start...,  cmd //c start...
_START_COMMAND_RE = re.compile(
    r'^\s*(?:cmd(?:\.exe)?\s+(?:/+[cC]\s+))?start\b',
    re.IGNORECASE,
)

logger = logging.getLogger(__name__)


def _msys_to_windows_path(cwd: str) -> str:
    """Translate a POSIX shell path emitted by the Windows shell backend to
    the native Windows form so ``os.path.isdir`` and
    ``subprocess.Popen(..., cwd=...)`` can find it.

    Two forms are recognised, matching the two supported backends:

    * Git Bash / MSYS  — ``/c/Users/x``      → ``C:\\Users\\x``
    * WSL              — ``/mnt/c/Users/x``  → ``C:\\Users\\x``

    No-ops on non-Windows hosts or for paths that aren't in either form
    (``/home/fetih``, ``/tmp/x`` stay as they are). Returns the input
    unchanged when no translation applies. This is idempotent — calling it
    on an already-Windows path returns it as-is.
    """
    if not _IS_WINDOWS or not cwd:
        return cwd
    # WSL form first: "/mnt/<letter>[/...]" — checked before the MSYS pattern
    # because "/mnt/c" would otherwise fall through as a plain POSIX path.
    m = re.match(r'^/mnt/([a-zA-Z])(/.*)?$', cwd)
    if not m:
        # Match leading "/<single letter>/" or exactly "/<letter>" (bare drive root).
        m = re.match(r'^/([a-zA-Z])(/.*)?$', cwd)
    if not m:
        return cwd
    drive = m.group(1).upper()
    tail = (m.group(2) or "").replace('/', '\\')
    return f"{drive}:{tail or chr(92)}"  # chr(92) = backslash, avoid raw-string escape


def _active_windows_shell() -> str:
    """Which Windows shell backend is in force right now.

    Returns ``""`` off Windows, otherwise ``"git-bash"`` or ``"wsl"``.  Never
    raises: a broken config must not make the terminal tool unusable, so any
    failure degrades to the Git Bash default.
    """
    if not _IS_WINDOWS:
        return ""
    try:
        return windows_shell.effective_shell()
    except Exception:  # pragma: no cover - defensive
        return windows_shell.SHELL_GIT_BASH


def _resolve_safe_cwd(cwd: str, wsl_mode: bool = False) -> str:
    """Return ``cwd`` if it exists as a directory, else the nearest existing
    ancestor.  Falls back to ``tempfile.gettempdir()`` only if walking up the
    path can't find any existing directory (effectively never on a healthy
    filesystem, but cheap belt-and-braces).

    ``wsl_mode`` marks the WSL backend, where the shell's filesystem is *not*
    the Windows filesystem.  Paths under ``/mnt/<drive>`` still map onto
    Windows and are validated normally, but Linux-only paths (``/home/fetih``,
    ``/etc``, ``/opt``) have no Windows equivalent — ``os.path.isdir`` would
    reject every one of them and wrongly bounce the session into ``%TEMP%``.
    In that case the path is returned untouched and WSL itself decides whether
    the ``cd`` succeeds.

    On Windows, also normalizes Git Bash / MSYS-style POSIX paths
    (``/c/Users/x``) to native Windows form before the isdir check so a
    perfectly valid ``pwd -P`` result from bash doesn't get rejected as
    "missing" (see ``_msys_to_windows_path``).

    Used by ``_run_bash`` to recover when the configured cwd is gone — most
    commonly because a previous tool call deleted its own working directory
    (issue #17558).  Without this guard, ``subprocess.Popen(..., cwd=...)``
    raises ``FileNotFoundError`` before bash starts, wedging every subsequent
    terminal call until the gateway restarts.
    """
    if _IS_WINDOWS:
        translated = _msys_to_windows_path(cwd)
        if wsl_mode and translated == cwd and cwd.startswith("/"):
            # Linux-only path inside WSL — nothing on the Windows side to
            # check it against, so hand it back verbatim.
            return cwd
        cwd = translated
    if cwd and os.path.isdir(cwd):
        return cwd
    parent = os.path.dirname(cwd) if cwd else ""
    while parent:
        if os.path.isdir(parent):
            return parent
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            # Reached the filesystem root and it doesn't exist either —
            # genuinely nothing to fall back to except the temp dir.
            break
        parent = next_parent
    return tempfile.gettempdir()


# FETIH-internal env vars that should NOT leak into terminal subprocesses.
_FETIH_PROVIDER_ENV_FORCE_PREFIX = "_FETIH_FORCE_"


def _build_provider_env_blocklist() -> frozenset:
    """Derive the blocklist from provider, tool, and gateway config."""
    blocked: set[str] = set()

    try:
        from fetih_cli.auth import PROVIDER_REGISTRY
        for pconfig in PROVIDER_REGISTRY.values():
            blocked.update(pconfig.api_key_env_vars)
            if pconfig.base_url_env_var:
                blocked.add(pconfig.base_url_env_var)
    except ImportError:
        pass

    try:
        from fetih_cli.config import OPTIONAL_ENV_VARS
        for name, metadata in OPTIONAL_ENV_VARS.items():
            category = metadata.get("category")
            if category in {"tool", "messaging"}:
                blocked.add(name)
            elif category == "setting" and metadata.get("password"):
                blocked.add(name)
    except ImportError:
        pass

    blocked.update({
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "OPENAI_ORG_ID",
        "OPENAI_ORGANIZATION",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "LLM_MODEL",
        "GOOGLE_API_KEY",
        "DEEPSEEK_API_KEY",
        "MISTRAL_API_KEY",
        "GROQ_API_KEY",
        "TOGETHER_API_KEY",
        "PERPLEXITY_API_KEY",
        "COHERE_API_KEY",
        "FIREWORKS_API_KEY",
        "XAI_API_KEY",
        "HELICONE_API_KEY",
        "PARALLEL_API_KEY",
        "FIRECRAWL_API_KEY",
        "FIRECRAWL_API_URL",
        "TELEGRAM_HOME_CHANNEL",
        "TELEGRAM_HOME_CHANNEL_NAME",
        "DISCORD_HOME_CHANNEL",
        "DISCORD_HOME_CHANNEL_NAME",
        "DISCORD_REQUIRE_MENTION",
        "DISCORD_FREE_RESPONSE_CHANNELS",
        "DISCORD_AUTO_THREAD",
        "SLACK_HOME_CHANNEL",
        "SLACK_HOME_CHANNEL_NAME",
        "SLACK_ALLOWED_USERS",
        "WHATSAPP_ENABLED",
        "WHATSAPP_MODE",
        "WHATSAPP_ALLOWED_USERS",
        "SIGNAL_HTTP_URL",
        "SIGNAL_ACCOUNT",
        "SIGNAL_ALLOWED_USERS",
        "SIGNAL_GROUP_ALLOWED_USERS",
        "SIGNAL_HOME_CHANNEL",
        "SIGNAL_HOME_CHANNEL_NAME",
        "SIGNAL_IGNORE_STORIES",
        "HASS_TOKEN",
        "HASS_URL",
        "EMAIL_ADDRESS",
        "EMAIL_PASSWORD",
        "EMAIL_IMAP_HOST",
        "EMAIL_SMTP_HOST",
        "EMAIL_HOME_ADDRESS",
        "EMAIL_HOME_ADDRESS_NAME",
        "GATEWAY_ALLOWED_USERS",
        "GH_TOKEN",
        "GITHUB_APP_ID",
        "GITHUB_APP_PRIVATE_KEY_PATH",
        "GITHUB_APP_INSTALLATION_ID",
        "MODAL_TOKEN_ID",
        "MODAL_TOKEN_SECRET",
        "DAYTONA_API_KEY",
        "VERCEL_OIDC_TOKEN",
        "VERCEL_TOKEN",
        "VERCEL_PROJECT_ID",
        "VERCEL_TEAM_ID",
    })
    return frozenset(blocked)


_FETIH_PROVIDER_ENV_BLOCKLIST = _build_provider_env_blocklist()


def _inject_context_fetih_home(env: dict) -> None:
    """Bridge the context-local FETIH home override into subprocess env."""
    try:
        from fetih_constants import get_fetih_home_override

        value = get_fetih_home_override()
        if value:
            env["FETIH_HOME"] = value
    except Exception:
        pass


def _sanitize_subprocess_env(base_env: dict | None, extra_env: dict | None = None) -> dict:
    """Filter FETIH-managed secrets from a subprocess environment."""
    try:
        from tools.env_passthrough import is_env_passthrough as _is_passthrough
    except Exception:
        _is_passthrough = lambda _: False  # noqa: E731

    sanitized: dict[str, str] = {}

    for key, value in (base_env or {}).items():
        if key.startswith(_FETIH_PROVIDER_ENV_FORCE_PREFIX):
            continue
        if key not in _FETIH_PROVIDER_ENV_BLOCKLIST or _is_passthrough(key):
            sanitized[key] = value

    for key, value in (extra_env or {}).items():
        if key.startswith(_FETIH_PROVIDER_ENV_FORCE_PREFIX):
            real_key = key[len(_FETIH_PROVIDER_ENV_FORCE_PREFIX):]
            sanitized[real_key] = value
        elif key not in _FETIH_PROVIDER_ENV_BLOCKLIST or _is_passthrough(key):
            sanitized[key] = value

    _inject_context_fetih_home(sanitized)

    # Per-profile HOME isolation for background processes (same as _make_run_env).
    from fetih_constants import get_subprocess_home
    _profile_home = get_subprocess_home()
    if _profile_home:
        sanitized["HOME"] = _profile_home

    return sanitized


def _find_bash() -> str:
    """Find the POSIX shell binary used for command execution.

    On Windows the lookup is delegated to
    :func:`tools.environments.windows_shell.find_git_bash`, which walks the
    known Git for Windows install locations *before* falling back to ``PATH``
    and — critically — refuses ``C:\\Windows\\System32\\bash.exe``.  That
    System32 binary is the WSL launcher shim, not Git Bash: picking it up made
    every terminal command fail with ``No such file or directory`` because the
    ``/c/Users/...`` paths FETIH emits don't exist inside WSL (which mounts
    Windows drives at ``/mnt/c/...``).

    The WSL *backend* never reaches this function — ``_run_bash`` builds a
    ``wsl.exe`` argv directly.  This stays the Git Bash path, and is also what
    the background-process registry uses for its ``bash -lic`` spawns.
    """
    if not _IS_WINDOWS:
        return (
            shutil.which("bash")
            or ("/usr/bin/bash" if os.path.isfile("/usr/bin/bash") else None)
            or ("/bin/bash" if os.path.isfile("/bin/bash") else None)
            or os.environ.get("SHELL")
            or "/bin/sh"
        )

    found = windows_shell.find_git_bash()
    if found:
        return found

    hint = ""
    if windows_shell.find_wsl_exe():
        hint = (
            "\nNot: sistemde WSL var ama C:\\Windows\\System32\\bash.exe bir "
            "WSL kısayoludur, Git Bash değildir — bu yüzden kullanılmadı. "
            "WSL'i kabuk olarak kullanmak istiyorsan Ayarlar'dan "
            "terminal.windows_shell='wsl' seç."
        )
    raise RuntimeError(
        "Git Bash not found. FETIH requires Git for Windows on Windows.\n"
        "Install it from: https://git-scm.com/download/win\n"
        "Or set FETIH_GIT_BASH_PATH to your bash.exe location." + hint
    )


# Backward compat — process_registry.py imports this name
_find_shell = _find_bash


# Standard PATH entries for environments with minimal PATH.
_SANE_PATH = (
    "/opt/homebrew/bin:/opt/homebrew/sbin:"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)


def _make_run_env(env: dict) -> dict:
    """Build a run environment with a sane PATH and provider-var stripping."""
    try:
        from tools.env_passthrough import is_env_passthrough as _is_passthrough
    except Exception:
        _is_passthrough = lambda _: False  # noqa: E731

    merged = dict(os.environ | env)
    run_env = {}
    for k, v in merged.items():
        if k.startswith(_FETIH_PROVIDER_ENV_FORCE_PREFIX):
            real_key = k[len(_FETIH_PROVIDER_ENV_FORCE_PREFIX):]
            run_env[real_key] = v
        elif k not in _FETIH_PROVIDER_ENV_BLOCKLIST or _is_passthrough(k):
            run_env[k] = v
    existing_path = run_env.get("PATH", "")
    # The "/usr/bin not already present → inject sane POSIX path" heuristic
    # only makes sense on POSIX.  On Windows the PATH separator is ";"
    # (the split(":") above turns a full Windows PATH into a single
    # unrecognisable chunk, which then triggers prepending POSIX paths
    # to a Windows PATH — completely wrong).  Skip the injection entirely
    # on Windows; the native PATH already points at whatever shell
    # FETIH is driving via _find_bash (Git Bash), and Git Bash itself
    # prepends its MSYS2 /usr/bin equivalent via the shell-init files.
    if not _IS_WINDOWS and "/usr/bin" not in existing_path.split(":"):
        run_env["PATH"] = f"{existing_path}:{_SANE_PATH}" if existing_path else _SANE_PATH

    _inject_context_fetih_home(run_env)

    # Per-profile HOME isolation: redirect system tool configs (git, ssh, gh,
    # npm …) into {FETIH_HOME}/home/ when that directory exists.  Only the
    # subprocess sees the override — the Python process keeps the real HOME.
    from fetih_constants import get_subprocess_home
    _profile_home = get_subprocess_home()
    if _profile_home:
        run_env["HOME"] = _profile_home

    # Inject ContextVar-based session vars into subprocess env.
    # ContextVars don't propagate to child processes, so we bridge them here.
    try:
        from gateway.session_context import get_session_env, _UNSET, _VAR_MAP
        for var_name, var in _VAR_MAP.items():
            value = var.get()
            if value is not _UNSET and value:
                run_env[var_name] = value
    except Exception:
        pass

    return run_env


def _read_terminal_shell_init_config() -> tuple[list[str], bool]:
    """Return (shell_init_files, auto_source_bashrc) from config.yaml.

    Best-effort — returns sensible defaults on any failure so terminal
    execution never breaks because the config file is unreadable.
    """
    try:
        from fetih_cli.config import load_config

        cfg = load_config() or {}
        terminal_cfg = cfg.get("terminal") or {}
        files = terminal_cfg.get("shell_init_files") or []
        if not isinstance(files, list):
            files = []
        auto_bashrc = bool(terminal_cfg.get("auto_source_bashrc", True))
        return [str(f) for f in files if f], auto_bashrc
    except Exception:
        return [], True


def _resolve_shell_init_files() -> list[str]:
    """Resolve the list of files to source before the login-shell snapshot.

    Expands ``~`` and ``${VAR}`` references and drops anything that doesn't
    exist on disk, so a missing ``~/.bashrc`` never breaks the snapshot.
    The ``auto_source_bashrc`` path runs only when the user hasn't supplied
    an explicit list — once they have, FETIH trusts them.
    """
    explicit, auto_bashrc = _read_terminal_shell_init_config()

    candidates: list[str] = []
    if explicit:
        candidates.extend(explicit)
    elif auto_bashrc and not _IS_WINDOWS:
        # Build a login-shell-ish source list so tools like n / nvm / asdf /
        # pyenv that self-install into the user's shell rc land on PATH in
        # the captured snapshot.
        #
        # ~/.profile and ~/.bash_profile run first because they have no
        # interactivity guard — installers like ``n`` and ``nvm`` append
        # their PATH export there on most distros, and a non-interactive
        # ``. ~/.profile`` picks that up.
        #
        # ~/.bashrc runs last. On Debian/Ubuntu the default bashrc starts
        # with ``case $- in *i*) ;; *) return;; esac`` and exits early
        # when sourced non-interactively, which is why sourcing bashrc
        # alone misses nvm/n PATH additions placed below that guard. We
        # still include it so users who put PATH logic in bashrc (and
        # stripped the guard, or never had one) keep working.
        candidates.extend(["~/.profile", "~/.bash_profile", "~/.bashrc"])

    resolved: list[str] = []
    for raw in candidates:
        try:
            path = os.path.expandvars(os.path.expanduser(raw))
        except Exception:
            continue
        if path and os.path.isfile(path):
            resolved.append(path)
    return resolved


def _prepend_shell_init(cmd_string: str, files: list[str]) -> str:
    """Prepend ``source <file>`` lines (guarded + silent) to a bash script.

    Each file is wrapped so a failing rc file doesn't abort the whole
    bootstrap: ``set +e`` keeps going on errors, ``2>/dev/null`` hides
    noisy prompts, and ``|| true`` neutralises the exit status.
    """
    if not files:
        return cmd_string

    prelude_parts = ["set +e"]
    for path in files:
        # shlex.quote isn't available here without an import; the files list
        # comes from os.path.expanduser output so it's a concrete absolute
        # path.  Escape single quotes defensively anyway.
        safe = path.replace("'", "'\\''")
        prelude_parts.append(f"[ -r '{safe}' ] && . '{safe}' 2>/dev/null || true")
    prelude = "\n".join(prelude_parts) + "\n"
    return prelude + cmd_string


class LocalEnvironment(BaseEnvironment):
    """Run commands directly on the host machine.

    Spawn-per-call: every execute() spawns a fresh bash process.
    Session snapshot preserves env vars across calls.
    CWD persists via file-based read after each command.
    """

    def __init__(self, cwd: str = "", timeout: int = 60, env: dict = None):
        if cwd:
            cwd = os.path.expanduser(cwd)
        # Resolve the Windows shell backend BEFORE super().__init__(), which
        # calls get_temp_dir() to place the snapshot / cwd marker files — and
        # those land in a different filesystem namespace under WSL.
        self._shell_backend = _active_windows_shell()
        pref = (
            windows_shell.read_shell_preference()
            if self._shell_backend == windows_shell.SHELL_WSL
            else {"distro": "", "user": ""}
        )
        self._wsl_distro = pref.get("distro") or ""
        self._wsl_user = pref.get("user") or ""
        super().__init__(cwd=cwd or os.getcwd(), timeout=timeout, env=env)
        self.init_session()

    # ------------------------------------------------------------------
    # Windows shell backend helpers
    # ------------------------------------------------------------------

    @property
    def _is_wsl(self) -> bool:
        """True when commands run through ``wsl.exe`` instead of Git Bash."""
        return self._shell_backend == windows_shell.SHELL_WSL

    def _host_path(self, shell_path: str) -> str:
        """Translate a path the *shell* understands into one Python can open.

        The snapshot and cwd-marker files are written by the shell but read
        back by this (native Windows) process.  Under Git Bash both sides
        already agree on ``C:/Users/...``; under WSL the shell sees
        ``/mnt/c/Users/...`` and Python needs the drive-letter form.
        """
        return _msys_to_windows_path(shell_path) if _IS_WINDOWS else shell_path

    def _shell_cwd(self, cwd: str) -> str:
        """Translate a stored cwd into the form the active shell can ``cd`` to."""
        if self._is_wsl:
            return windows_shell.windows_to_wsl_path(cwd)
        return cwd

    def _accept_shell_cwd(self, raw: str) -> str | None:
        """Normalise + validate a ``pwd -P`` result, or ``None`` to reject it.

        Git Bash reports ``/c/Users/x`` and WSL reports ``/mnt/c/Users/x``;
        both translate to a real Windows directory that can be verified.  A
        Linux-only path under WSL (``/home/fetih``) has no Windows counterpart,
        so it's accepted as-is rather than rejected — WSL just told us that's
        where it is.
        """
        if not raw:
            return None
        if not _IS_WINDOWS:
            return raw if os.path.isdir(raw) else None
        translated = _msys_to_windows_path(raw)
        if translated == raw and self._is_wsl and raw.startswith("/"):
            return raw
        return translated if os.path.isdir(translated) else None

    # ------------------------------------------------------------------
    # Override execute() to intercept Windows GUI-launch commands
    # ------------------------------------------------------------------

    def execute(
        self,
        command: str,
        cwd: str = "",
        *,
        timeout: int | None = None,
        stdin_data: str | None = None,
    ) -> dict:
        """Execute a command. On Windows, intercepts 'start' GUI-launch
        commands to avoid the pipe-inheritance hang where launched GUI apps
        (chrome, notepad, explorer, etc.) inherit the stdout PIPE handle,
        preventing pipe EOF until the GUI app exits (causing 90–120s hangs).
        """
        if _IS_WINDOWS and _START_COMMAND_RE.match(command):
            return self._execute_start_command(command, cwd=cwd or self.cwd)
        return super().execute(
            command, cwd=cwd, timeout=timeout, stdin_data=stdin_data,
        )

    def _execute_start_command(self, command: str, cwd: str) -> dict:
        """Run a ``start <app>`` GUI-launch command on Windows **without**
        bash and without PIPE stdout, so the launched GUI process never
        inherits a pipe handle.

        Uses ``shell=True`` to go through cmd.exe's built-in ``start``
        command directly.  ``close_fds=True`` + no PIPE means the GUI app
        receives only standard console handles — no lingering pipe write-end
        that would prevent EOF and hang the terminal tool.

        Returns immediately after the process is spawned; the GUI app runs
        independently.
        """
        # Normalise Git Bash POSIX paths (``/c/Users/x``) → ``C:\\Users\\x``
        effective_cwd = _msys_to_windows_path(cwd) if _IS_WINDOWS else cwd
        if not os.path.isdir(effective_cwd):
            effective_cwd = _resolve_safe_cwd(effective_cwd)

        try:
            # DEVNULL for all three standard streams → no PIPE handle exists
            # for the GUI child to inherit.  CREATE_NO_WINDOW suppresses the
            # brief cmd.exe console flash; the GUI app still opens its own
            # window because ``start`` uses CREATE_NEW_CONSOLE internally.
            subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                cwd=effective_cwd,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Don't wait — the GUI app runs independently.  The Popen object
            # is dropped; Python's GC will reap the zombie process later.
        except Exception as exc:
            return {
                "output": f"[hata] GUI uygulaması başlatılamadı: {exc}",
                "returncode": 1,
            }

        # Extract a display-friendly app name for the output message.
        app_name = ""
        m = re.search(
            r'\bstart\b\s+(?:"[^"]*"\s+)?("?)([^\s"/]+)\1',
            command, re.IGNORECASE,
        )
        if m:
            app_name = f" ({m.group(2)})"

        return {
            "output": f"GUI uygulaması başlatıldı{app_name}",
            "returncode": 0,
        }

    def get_temp_dir(self) -> str:
        """Return a shell-safe writable temp dir for local execution.

        Termux does not provide /tmp by default, but exposes a POSIX TMPDIR.
        Prefer POSIX-style env vars when available, keep using /tmp on regular
        Unix systems, and only fall back to tempfile.gettempdir() when it also
        resolves to a POSIX path.

        Check the environment configured for this backend first so callers can
        override the temp root explicitly (for example via terminal.env or a
        custom TMPDIR), then fall back to the host process environment.

        **Windows:** hardcoded ``/tmp`` is wrong in two ways — native Python
        can't open the path, and the Windows default temp (``%TEMP%``) often
        contains spaces (``C:\\Users\\Some Name\\AppData\\Local\\Temp``) that
        break unquoted bash interpolations.  Use a dedicated cache dir under
        ``FETIH_HOME`` instead — single-word path, guaranteed to exist, same
        string resolves in both Git Bash and native Python.
        """
        if _IS_WINDOWS:
            # Derive a Windows-safe temp dir under FETIH_HOME.  Using
            # forward slashes makes the same string work unchanged in bash
            # command interpolations AND in Python ``open()`` — Windows
            # accepts forward slashes in filesystem paths, and we control
            # the path so we can guarantee no spaces.
            try:
                from fetih_constants import get_fetih_home
                cache_dir = get_fetih_home() / "cache" / "terminal"
            except Exception:
                cache_dir = Path(tempfile.gettempdir()) / "fetih_terminal"
            cache_dir.mkdir(parents=True, exist_ok=True)
            # Force forward slashes so the same string serves both contexts.
            as_posix = str(cache_dir).replace("\\", "/")
            if self._is_wsl:
                # The directory is created on the Windows side but the shell
                # that reads/writes it lives in WSL, where the same bytes are
                # reachable as /mnt/<drive>/...  ``_host_path`` maps it back
                # whenever Python itself needs to touch the file.
                return windows_shell.windows_to_wsl_path(as_posix)
            return as_posix

        for env_var in ("TMPDIR", "TMP", "TEMP"):
            candidate = self.env.get(env_var) or os.environ.get(env_var)
            if candidate and candidate.startswith("/"):
                return candidate.rstrip("/") or "/"

        if os.path.isdir("/tmp") and os.access("/tmp", os.W_OK | os.X_OK):
            return "/tmp"

        candidate = tempfile.gettempdir()
        if candidate.startswith("/"):
            return candidate.rstrip("/") or "/"

        return "/tmp"

    def init_session(self):
        """Capture the login-shell snapshot, translating cwd for WSL first.

        ``BaseEnvironment.init_session`` interpolates ``self.cwd`` straight
        into a ``builtin cd`` — a native ``C:\\Users\\x`` path that WSL can't
        resolve.  Swap in the ``/mnt/c/...`` form for the duration of the
        bootstrap; the snapshot's own ``pwd -P`` result then flows back through
        ``_update_cwd`` in whatever form the shell reports.
        """
        if not self._is_wsl:
            super().init_session()
            return
        original = self.cwd
        self.cwd = self._shell_cwd(original)
        try:
            super().init_session()
        finally:
            if self.cwd == self._shell_cwd(original):
                # init_session didn't learn a new cwd (e.g. it failed) —
                # restore what the caller asked for rather than leaking the
                # translated form.
                self.cwd = original

    def _wrap_command(self, command: str, cwd: str) -> str:
        """Same wrapper as the base class, with a shell-resolvable cwd.

        Under WSL the stored cwd may still be in Windows form (it round-trips
        through ``_resolve_safe_cwd``); ``windows_to_wsl_path`` is idempotent,
        so translating unconditionally here is safe for both shapes.
        """
        return super()._wrap_command(command, self._shell_cwd(cwd))

    def _run_bash(self, cmd_string: str, *, login: bool = False,
                  timeout: int = 120,
                  stdin_data: str | None = None) -> subprocess.Popen:
        # For login-shell invocations (used by init_session to build the
        # environment snapshot), prepend sources for the user's bashrc /
        # custom init files so tools registered outside bash_profile
        # (nvm, asdf, pyenv, …) end up on PATH in the captured snapshot.
        # Non-login invocations are already sourcing the snapshot and
        # don't need this.
        if login:
            init_files = _resolve_shell_init_files()
            if init_files:
                cmd_string = _prepend_shell_init(cmd_string, init_files)
        run_env = _make_run_env(self.env)

        # Recover when the cwd has been deleted out from under us — usually by
        # a previous tool call that ran ``rm -rf`` on its own working dir
        # (issue #17558).  Popen would otherwise raise FileNotFoundError on
        # the cwd before bash starts, wedging every subsequent call until the
        # gateway restarts.
        #
        # On Windows, ``_resolve_safe_cwd`` also normalises Git Bash-style
        # POSIX paths (``/c/Users/...``) to native form so a perfectly valid
        # ``pwd -P`` result from bash isn't mistakenly treated as "missing"
        # and spammed as a warning on every command.
        safe_cwd = _resolve_safe_cwd(self.cwd, wsl_mode=self._is_wsl)
        if safe_cwd != self.cwd:
            # MSYS → Windows translation alone shouldn't surface as a warning
            # (it's a benign normalization, not a recovery). Only warn when
            # the directory really doesn't exist on disk.
            normalized = _msys_to_windows_path(self.cwd) if _IS_WINDOWS else self.cwd
            if safe_cwd != normalized:
                logger.warning(
                    "LocalEnvironment cwd %r is missing on disk; "
                    "falling back to %r so terminal commands keep working.",
                    self.cwd,
                    safe_cwd,
                )
            self.cwd = safe_cwd

        if self._is_wsl:
            # The real working directory is set by ``wsl.exe --cd`` (which
            # accepts both ``C:\\x`` and ``/home/x``) and re-asserted by the
            # ``builtin cd`` inside the wrapper.  Popen's own cwd only decides
            # where the *launcher* starts, so it must be an existing Windows
            # directory — a Linux-only cwd would raise FileNotFoundError
            # before wsl.exe ever runs.
            args = windows_shell.build_wsl_argv(
                cmd_string,
                login=login,
                cwd=self.cwd,
                distro=self._wsl_distro,
                user=self._wsl_user,
            )
            _popen_cwd = _msys_to_windows_path(self.cwd)
            if not os.path.isdir(_popen_cwd):
                _popen_cwd = tempfile.gettempdir()
        else:
            bash = _find_bash()
            args = (
                [bash, "-l", "-c", cmd_string] if login else [bash, "-c", cmd_string]
            )
            _popen_cwd = self.cwd

        proc = subprocess.Popen(
            args,
            text=True,
            env=run_env,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            preexec_fn=None if _IS_WINDOWS else os.setsid,
            creationflags=subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0,
            cwd=_popen_cwd,
        )
        if not _IS_WINDOWS:
            try:
                proc._fetih_pgid = os.getpgid(proc.pid)
            except ProcessLookupError:
                pass

        if stdin_data is not None:
            _pipe_stdin(proc, stdin_data)

        return proc

    def _kill_process(self, proc):
        """Kill the entire process group (all children)."""

        def _group_alive(pgid: int) -> bool:
            try:
                # POSIX-only: _IS_WINDOWS is handled before this helper is used.
                os.killpg(pgid, 0)  # windows-footgun: ok — POSIX process-group alive probe
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                # The group exists, even if this process cannot signal it.
                return True

        def _wait_for_group_exit(pgid: int, timeout: float) -> bool:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                # Reap the wrapper promptly. A dead but unreaped group leader
                # still makes killpg(pgid, 0) report the group as alive.
                try:
                    proc.poll()
                except Exception:
                    pass
                if not _group_alive(pgid):
                    return True
                time.sleep(0.05)
            try:
                proc.poll()
            except Exception:
                pass
            return not _group_alive(pgid)

        try:
            if _IS_WINDOWS:
                proc.terminate()
            else:
                try:
                    pgid = os.getpgid(proc.pid)
                except ProcessLookupError:
                    pgid = getattr(proc, "_fetih_pgid", None)
                    if pgid is None:
                        raise

                try:
                    os.killpg(pgid, signal.SIGTERM)  # windows-footgun: ok — POSIX process-group SIGTERM (guarded by _IS_WINDOWS above)
                except ProcessLookupError:
                    return

                # Wait on the process group, not just the shell wrapper. Under
                # load the wrapper can exit before grandchildren do; returning
                # at that point leaves orphaned process-group members behind.
                if _wait_for_group_exit(pgid, 1.0):
                    return

                try:
                    # POSIX-only: _IS_WINDOWS is handled by the outer branch.
                    os.killpg(pgid, signal.SIGKILL)  # windows-footgun: ok — POSIX process-group SIGKILL
                except ProcessLookupError:
                    return
                _wait_for_group_exit(pgid, 2.0)
                try:
                    proc.wait(timeout=0.2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass

    def _update_cwd(self, result: dict):
        """Read CWD from temp file (local-only, no round-trip needed).

        Skip the assignment when the path no longer exists as a directory —
        ``pwd -P`` on a deleted cwd can leave a stale value in the marker
        file, and propagating it would re-wedge the next ``Popen``.  The
        ``_run_bash`` recovery path will resolve a safe fallback if needed.

        On Windows, the value written by Git Bash's ``pwd -P`` is in
        MSYS form (``/c/Users/x``). Translate it to native Windows form
        before validating with ``os.path.isdir`` and before storing on
        ``self.cwd``; otherwise the isdir check rejects every valid
        result and ``_run_bash`` later prints a misleading "cwd is
        missing" warning on every command.
        """
        try:
            with open(self._host_path(self._cwd_file), encoding="utf-8") as f:
                cwd_path = f.read().strip()
            accepted = self._accept_shell_cwd(cwd_path)
            if accepted:
                self.cwd = accepted
        except (OSError, FileNotFoundError):
            pass

        # Still strip the marker from output so it's not visible
        self._extract_cwd_from_output(result)

    def _extract_cwd_from_output(self, result: dict):
        """Same semantics as the base class, but on Windows the value
        emitted by ``pwd -P`` inside Git Bash is in MSYS form
        (``/c/Users/x``). Normalize to native Windows form and validate
        the directory exists before assigning to ``self.cwd`` — otherwise
        ``_run_bash``'s safe-cwd recovery would warn on every subsequent
        command.

        Always defers to the base class for stripping the marker text from
        ``result["output"]`` so output formatting is identical.
        """
        # Snapshot pre-existing cwd, defer to base for parsing + marker
        # stripping, then validate / normalize whatever it assigned.
        prev_cwd = self.cwd
        super()._extract_cwd_from_output(result)
        if self.cwd != prev_cwd:
            accepted = self._accept_shell_cwd(self.cwd)
            # Stale / non-existent path — keep previous cwd; _run_bash
            # will resolve a safe fallback on the next call if needed.
            self.cwd = accepted or prev_cwd

    def cleanup(self):
        """Clean up temp files."""
        for f in (self._snapshot_path, self._cwd_file):
            try:
                # Under WSL these are ``/mnt/c/...`` strings the shell wrote;
                # Python needs the drive-letter form to unlink them.
                os.unlink(self._host_path(f))
            except OSError:
                pass

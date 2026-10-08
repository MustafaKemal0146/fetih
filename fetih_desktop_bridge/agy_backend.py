"""Google Antigravity CLI (``agy``) as a desktop-bridge session backend.

Lets a user with a Google AI Pro/Ultra subscription chat through the desktop
app *without* an API key: each turn runs Google's own, officially installed
``agy`` binary in its documented headless mode (``agy -p``) under the user's
own ``agy`` login, so usage counts against their Antigravity quota. Nothing
here reads, copies or replays ``agy``'s credentials.

Trade-off, surfaced to the user in the UI: in this mode the *Antigravity*
agent runs the turn, not FETİH's. FETİH's tools, skills, approval flow and
findings do not apply. Headless ``agy`` auto-denies any tool that needs a
permission prompt unless ``--dangerously-skip-permissions`` is passed; that is
opt-in via ``desktop.antigravity.allow_tools`` (default off).

Turns are stateless on the ``agy`` side: prior turns are folded into the
prompt from FETİH's own transcript. ``-p`` does not report a conversation id,
and resuming "the most recent" conversation would cross wires between parallel
FETİH sessions or the user's own ``agy`` use.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Desktop-only provider id. Not a CLI provider: the bridge intercepts it
#: before ``resolve_runtime_provider`` (which would reject it).
PROVIDER_ID = "antigravity-cli"

#: ``agy models`` is a network round-trip; cache it briefly.
_MODELS_TTL_S = 300.0
_models_cache: Dict[str, Any] = {"at": 0.0, "models": []}
_models_lock = threading.Lock()

#: Prior-turn budget folded into a stateless prompt.
_HISTORY_MAX_MESSAGES = 12
_HISTORY_MAX_CHARS = 12000

#: Marker ``agy -p`` writes to stderr when it auto-denied a tool.
_DENIED_MARKER = "auto-denied"

#: The prompt travels as a command-line argument; Windows caps the whole
#: command line at ~32K characters, so keep well under it.
_MAX_PROMPT_CHARS = 28000


def find_agy() -> Optional[str]:
    """Locate the ``agy`` executable (PATH first, then the default install)."""
    override = os.getenv("FETIH_AGY_PATH", "").strip()
    if override and Path(override).is_file():
        return override
    found = shutil.which("agy")
    if found:
        return found
    local = os.getenv("LOCALAPPDATA", "")
    if local:
        candidate = Path(local) / "agy" / "bin" / "agy.exe"
        if candidate.is_file():
            return str(candidate)
    home_candidate = Path.home() / ".local" / "bin" / "agy"
    if home_candidate.is_file():
        return str(home_candidate)
    return None


def _creationflags() -> int:
    # No console window flashing up behind the desktop app on Windows.
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def list_models(*, refresh: bool = False, runner: Optional[Callable[..., Any]] = None) -> List[str]:
    """Models the signed-in ``agy`` account can use (``agy models``).

    Returns ``[]`` when ``agy`` is missing, not signed in, or errors — callers
    treat that as "not available". Cached for a few minutes.
    """
    now = time.time()
    with _models_lock:
        if not refresh and _models_cache["models"] and now - _models_cache["at"] < _MODELS_TTL_S:
            return list(_models_cache["models"])

    exe = find_agy()
    if not exe:
        return []
    run = runner or subprocess.run
    try:
        proc = run(
            [exe, "models"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=45,
            creationflags=_creationflags(),
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    models = [
        line.strip()
        for line in (proc.stdout or "").splitlines()
        if line.strip() and " " not in line.strip()
    ]
    with _models_lock:
        _models_cache["at"] = now
        _models_cache["models"] = models
    return list(models)


def status() -> Dict[str, Any]:
    """Auth-status-shaped snapshot: installed + signed in (can list models)."""
    exe = find_agy()
    if not exe:
        return {
            "provider": PROVIDER_ID,
            "logged_in": False,
            "configured": False,
            "detail": "agy (Antigravity CLI) not installed",
            "auth_type": "external_process",
        }
    models = list_models()
    return {
        "provider": PROVIDER_ID,
        "logged_in": bool(models),
        "configured": bool(models),
        "source": "agy",
        "detail": "" if models else "agy is installed but not signed in — run `agy` once to sign in",
        "auth_type": "external_process",
    }


def compose_prompt(message: str, history: Optional[List[Dict[str, Any]]]) -> str:
    """Fold recent transcript turns into a single stateless prompt."""
    turns: List[str] = []
    for item in (history or [])[-_HISTORY_MAX_MESSAGES:]:
        role = str(item.get("role") or "")
        content = item.get("content")
        if isinstance(content, list):  # OpenAI content-parts shape
            content = " ".join(
                str(p.get("text", "")) for p in content if isinstance(p, dict)
            )
        text = str(content or "").strip()
        if role not in ("user", "assistant") or not text:
            continue
        label = "Kullanıcı" if role == "user" else "Asistan"
        turns.append(f"{label}: {text}")

    if not turns:
        return message

    transcript = "\n\n".join(turns)
    if len(transcript) > _HISTORY_MAX_CHARS:
        transcript = "…" + transcript[-_HISTORY_MAX_CHARS:]
    return (
        "Aşağıda bu sohbetin önceki kısmı var; bağlam olarak kullan, "
        "yalnızca son mesaja yanıt ver.\n\n"
        f"--- Önceki sohbet ---\n{transcript}\n--- Son mesaj ---\n{message}"
    )


class AgyCliAgent:
    """Bridge-session agent that delegates each turn to ``agy -p``.

    Implements the subset of the ``AIAgent`` surface the bridge touches:
    streaming callbacks, ``run_conversation``, ``interrupt`` and
    ``_session_messages`` (so history survives model switches).
    """

    def __init__(
        self,
        *,
        model: str,
        cwd: str,
        allow_tools: bool = False,
        popen: Optional[Callable[..., Any]] = None,
        exe: Optional[str] = None,
    ):
        self.model = model
        self.cwd = cwd
        self.allow_tools = allow_tools
        self._popen = popen or subprocess.Popen
        self._exe = exe
        self._proc: Optional[Any] = None
        self._interrupted = False

        self.stream_delta_callback = None
        self.reasoning_callback = None
        self.thinking_callback = None
        self.tool_start_callback = None
        self.tool_complete_callback = None
        self.suppress_status_output = True
        self.tool_gen_callback = None
        self._session_messages: List[Dict[str, Any]] = []

    def interrupt(self, *args, **kwargs) -> None:
        self._interrupted = True
        proc = self._proc
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

    def _args(self, prompt: str) -> List[str]:
        exe = self._exe or find_agy()
        if not exe:
            raise RuntimeError(
                "Antigravity CLI (agy) bulunamadı. Kurulum: https://antigravity.google"
            )
        args = [exe, "-p", prompt, "--print-timeout", "15m"]
        if self.model:
            args += ["--model", self.model]
        if self.allow_tools:
            args.append("--dangerously-skip-permissions")
        return args

    def run_conversation(
        self, message: str, conversation_history: Any = None, **_: Any
    ) -> Dict[str, Any]:
        self._interrupted = False
        history = list(conversation_history or [])
        prompt = compose_prompt(message, history)
        if len(prompt) > _MAX_PROMPT_CHARS:
            # Drop the folded history first; the new message matters most.
            prompt = message
        if len(prompt) > _MAX_PROMPT_CHARS:
            return {
                "failed": True,
                "error": (
                    f"Mesaj Antigravity için çok uzun ({len(prompt)} karakter; "
                    f"sınır {_MAX_PROMPT_CHARS}). Mesajı kısalt ya da başka bir "
                    "sağlayıcı kullan."
                ),
                "final_response": "",
            }

        if self.thinking_callback:
            try:
                self.thinking_callback("Antigravity çalışıyor…")
            except Exception:
                pass

        proc = self._popen(
            self._args(prompt),
            cwd=self.cwd or None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=_creationflags(),
        )
        self._proc = proc

        # Drain stderr on its own thread: reading stdout line-by-line while
        # stderr fills its pipe buffer would deadlock both sides.
        err_parts: List[str] = []

        def _drain_stderr() -> None:
            try:
                if proc.stderr is not None:
                    err_parts.append(proc.stderr.read())
            except Exception:
                pass

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        err_thread.start()

        chunks: List[str] = []
        try:
            for line in proc.stdout:  # streamed as agy prints
                chunks.append(line)
                if self.stream_delta_callback:
                    try:
                        self.stream_delta_callback(line)
                    except Exception:
                        pass
            proc.wait()
            err_thread.join(timeout=5)
        finally:
            self._proc = None
        stderr = "".join(err_parts)

        if self._interrupted:
            return {"failed": True, "error": "cancelled", "final_response": ""}

        text = "".join(chunks).strip()
        err = (stderr or "").strip()

        if proc.returncode != 0:
            return {
                "failed": True,
                "error": f"agy exited with code {proc.returncode}: {err[-500:] or 'no details'}",
                "final_response": "",
            }

        if not text:
            if _DENIED_MARKER in err:
                text = (
                    "Antigravity bu isteği yanıtlamak için bir araç (ör. komut) "
                    "çalıştırmak istedi, ancak araç izinleri kapalı olduğu için "
                    "istek reddedildi. İzin vermek için Ayarlar'da "
                    "'desktop.antigravity.allow_tools' seçeneğini aç (dikkat: "
                    "Antigravity komutları onay sormadan çalıştırır)."
                )
            elif err:
                return {"failed": True, "error": f"agy: {err[-500:]}", "final_response": ""}

        self._session_messages = history + [
            {"role": "user", "content": message},
            {"role": "assistant", "content": text},
        ]
        return {"final_response": text, "api_calls": 1}

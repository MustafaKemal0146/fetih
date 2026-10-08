"""Entry point for the FETİH Masaüstü Köprüsü.

    fetih desktop-bridge                  # WebSocket on 127.0.0.1, random port
    fetih desktop-bridge --port 18790     # fixed port
    fetih desktop-bridge --stdio          # NDJSON over stdin/stdout
    python -m fetih_desktop_bridge --stdio

Token handling
--------------
WebSocket mode requires a token.  It is taken from ``FETIH_BRIDGE_TOKEN`` when
the desktop app already generated one and passed it down the environment;
otherwise the bridge mints a fresh one per run and prints it on the handshake
line.  It is never written to disk.  ``--no-auth`` exists for local debugging
only and refuses to run unless ``--stdio`` or an explicit opt-in is given.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import socket
import sys
from typing import List, Optional

from . import BIND_HOST, PROTOCOL_VERSION
from .server import BridgeServer
from .transport import serve_stdio, serve_websocket


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((BIND_HOST, 0))
        return s.getsockname()[1]


def _start_warmup() -> None:
    """İlk mesajın ~25 sn beklememesi için ağır işleri arka planda ısıt.

    Soğuk başlangıç bedeli, kullanıcı daha hiçbir şey yazmadan ödensin:
    - ``run_agent`` import zinciri (model_tools + tüm tools/* keşfi + agent/*),
    - skill sistem-istem indeksi (``~/.fetih/skills`` ağacının taranması ve
      snapshot'ın hazırlanması) — asıl 25 sn'nin büyük kısmı budur.
    Hepsi daemon thread'de ve hatasız; başlatmayı asla bloklamaz.
    """
    import threading

    def _work() -> None:
        try:
            import run_agent  # noqa: F401 — ağır import zincirini ısıt
        except Exception:
            pass
        try:
            from agent.prompt_builder import build_skills_system_prompt

            build_skills_system_prompt()  # skill ağacını tara + snapshot'ı ısıt
        except Exception:
            pass

    threading.Thread(target=_work, daemon=True).start()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fetih desktop-bridge",
        description=(
            "Masaüstü Köprüsü — localhost-only JSON-RPC 2.0 (NDJSON) server "
            "that lets the native Windows shell drive the real FETİH agent."
        ),
    )
    p.add_argument("--stdio", action="store_true", help="NDJSON over stdin/stdout instead of WebSocket")
    p.add_argument("--port", type=int, default=0, help="WebSocket port (0 = pick a free one)")
    p.add_argument("--token", default="", help="shared token (default: $FETIH_BRIDGE_TOKEN or generated)")
    p.add_argument("--no-auth", action="store_true", help="disable the token check (stdio/debug only)")
    p.add_argument("--fake-model", action="store_true", help="use a deterministic fake model for manual UI testing")
    p.add_argument("--print-handshake", action="store_true", default=True, help=argparse.SUPPRESS)
    p.add_argument("--version", action="store_true", help="print the bridge protocol version and exit")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        print(json.dumps({"protocol_version": PROTOCOL_VERSION}))
        return 0

    token = (args.token or os.getenv("FETIH_BRIDGE_TOKEN") or "").strip()
    require_auth = not args.no_auth
    fake_model = args.fake_model or bool(os.getenv("FETIH_FAKE_MODEL"))

    # The desktop app is a security tool: dangerous commands must never run
    # unattended.  FETIH_EXEC_ASK routes them through the approval flow
    # (tools.approval), which blocks the agent thread and emits a
    # ``session.approval_request`` event the desktop can answer with
    # ``session.approve``.  Without this the agent runs in a non-interactive
    # context and auto-approves.  It is a per-process policy, set once here.
    os.environ.setdefault("FETIH_EXEC_ASK", "1")

    # Soğuk başlangıcı kullanıcı ilk mesajını yazmadan ısıt (fake model hariç).
    if not fake_model:
        _start_warmup()

    if args.stdio:
        # The parent process spawned us over a private pipe; it already holds
        # every privilege the bridge could grant, so a token adds nothing.
        server = BridgeServer(token=token, require_auth=require_auth and bool(token), fake_model=fake_model)
        try:
            return asyncio.run(serve_stdio(server, ready_frame=server.ready_frame()))
        except KeyboardInterrupt:
            return 0

    if require_auth and not token:
        token = secrets.token_urlsafe(32)

    if not require_auth:
        print(
            "fetih desktop-bridge: refusing to serve WebSocket with --no-auth. "
            "Use --stdio for unauthenticated local debugging.",
            file=sys.stderr,
        )
        return 2

    port = args.port or _free_port()
    server = BridgeServer(token=token, require_auth=True, fake_model=fake_model)

    def _announce(bound_port: int) -> None:
        # One machine-readable line on stdout so a launcher can parse it and
        # attach without scraping logs.  The token appears here and nowhere
        # else: not in the config, not in the logs, not on disk.
        print(
            json.dumps(
                {
                    "event": "bridge.listening",
                    "url": f"ws://{BIND_HOST}:{bound_port}",
                    "protocol_version": PROTOCOL_VERSION,
                    "token": token,
                    "pid": os.getpid(),
                }
            ),
            flush=True,
        )

    try:
        return asyncio.run(serve_websocket(server, port=port, on_listening=_announce))
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"fetih desktop-bridge: cannot bind {BIND_HOST}:{port} — {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"fetih desktop-bridge: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

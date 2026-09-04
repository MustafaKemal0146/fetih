"""Transports for the FETİH Masaüstü Köprüsü.

Two transports carry the *identical* NDJSON frames defined in
``protocol.py``, and both hand every inbound frame to the same
``BridgeServer.dispatch``:

* :class:`StdioTransport`     — NDJSON on stdin/stdout, for a desktop app that
                                spawns the Python process itself.  Implicitly
                                trusted: the parent process IS the client.
* :class:`WebSocketTransport` — ``ws://127.0.0.1:<port>``.  Loopback only, and
                                every connection must call
                                ``bridge.authenticate`` with the shared token
                                before any other method is accepted.

A :class:`Connection` is the server's handle on one client.  Method handlers
never touch a socket; they emit events through ``Connection.emit``.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, Awaitable, Callable, Dict, Optional

from . import BIND_HOST
from .protocol import decode, encode


class Connection:
    """One client attached to the bridge.

    ``authenticated`` starts True for stdio (the parent process spawned us and
    therefore already holds every privilege we could grant) and False for
    WebSocket, where the token exchange has to happen first.
    """

    __slots__ = ("_send", "authenticated", "kind", "peer", "_closed")

    def __init__(
        self,
        send: Callable[[str], Awaitable[None]],
        *,
        kind: str,
        authenticated: bool,
        peer: str = "",
    ):
        self._send = send
        self.kind = kind
        self.authenticated = authenticated
        self.peer = peer
        self._closed = False

    async def send_frame(self, frame: Dict[str, Any]) -> None:
        if self._closed:
            return
        try:
            await self._send(encode(frame))
        except Exception:
            # A client that vanished mid-turn must not abort the agent run.
            self._closed = True

    def emit_threadsafe(self, loop: asyncio.AbstractEventLoop, frame: Dict[str, Any]) -> None:
        """Queue an event from a worker thread (agent callbacks run there)."""
        if self._closed:
            return
        try:
            asyncio.run_coroutine_threadsafe(self.send_frame(frame), loop)
        except RuntimeError:
            pass

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed


# --- stdio ------------------------------------------------------------------


async def serve_stdio(server, *, ready_frame: Optional[Dict[str, Any]] = None) -> int:
    """Read NDJSON requests from stdin, write frames to stdout.

    Returns a process exit code.  EOF on stdin is a clean shutdown.
    """
    loop = asyncio.get_running_loop()
    write_lock = asyncio.Lock()

    async def _write(line: str) -> None:
        async with write_lock:
            await loop.run_in_executor(None, _blocking_write, line)

    def _blocking_write(line: str) -> None:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    conn = Connection(_write, kind="stdio", authenticated=True, peer="stdio")
    server.attach(conn, loop)

    if ready_frame is not None:
        await conn.send_frame(ready_frame)

    try:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            await server.handle_line(conn, line)
    finally:
        conn.close()
        server.detach(conn)
    return 0


# --- WebSocket --------------------------------------------------------------


async def serve_websocket(server, *, port: int, on_listening=None) -> int:
    """Serve the same dispatch over ``ws://127.0.0.1:<port>``.

    Binding is hard-wired to loopback (``BIND_HOST``).  This is a security
    tool; its own control channel must never be reachable from the network.
    """
    try:
        import websockets
    except ImportError as exc:  # pragma: no cover - dependency check
        raise RuntimeError(
            "The WebSocket transport needs the 'websockets' package. "
            "Install it, or run the bridge with --stdio."
        ) from exc

    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    async def handler(ws):
        peer = ""
        try:
            peer = "%s:%s" % ws.remote_address[:2]
        except Exception:
            pass

        conn = Connection(ws.send, kind="ws", authenticated=False, peer=peer)
        server.attach(conn, loop)
        await conn.send_frame(server.ready_frame())
        try:
            async for raw in ws:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                raw = raw.strip()
                if not raw:
                    continue
                await server.handle_line(conn, raw)
        except Exception:
            pass
        finally:
            conn.close()
            server.detach(conn)

    async with websockets.serve(handler, BIND_HOST, port, ping_interval=20):
        if on_listening is not None:
            on_listening(port)
        try:
            await stop
        except asyncio.CancelledError:
            pass
    return 0


__all__ = ["Connection", "serve_stdio", "serve_websocket", "decode"]

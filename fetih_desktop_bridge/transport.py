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

    __slots__ = ("_send", "authenticated", "kind", "peer", "_closed", "_send_lock")

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
        # Requests are now dispatched concurrently (see serve_*), so several
        # tasks may write to the same socket at once.  Serialize writes so two
        # frames never interleave on the wire.
        self._send_lock = asyncio.Lock()

    async def send_frame(self, frame: Dict[str, Any]) -> None:
        if self._closed:
            return
        encoded = encode(frame)
        try:
            async with self._send_lock:
                await self._send(encoded)
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


class _TaskSet:
    """Tracks in-flight request handlers so they can be awaited/cancelled.

    Each inbound frame is dispatched as its own task so the read loop keeps
    pulling frames while a ``session.send`` turn is parked in a worker thread.
    Without this, an approval response (or a second session) could never be
    read until the current turn finished — a deadlock, since the turn is
    itself blocked waiting for that very response.
    """

    def __init__(self) -> None:
        self._tasks: "set[asyncio.Task]" = set()

    def spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def drain(self) -> None:
        if not self._tasks:
            return
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*list(self._tasks), return_exceptions=True)


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
    tasks = _TaskSet()

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
            # Dispatch concurrently so the read loop stays responsive while a
            # turn is parked waiting on the agent (or on user approval).
            tasks.spawn(server.handle_line(conn, line))
    finally:
        conn.close()
        await tasks.drain()
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
        tasks = _TaskSet()
        await conn.send_frame(server.ready_frame())
        try:
            async for raw in ws:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                raw = raw.strip()
                if not raw:
                    continue
                # Concurrent dispatch — see serve_stdio for why this is
                # required (approval responses must be readable mid-turn).
                tasks.spawn(server.handle_line(conn, raw))
        except Exception:
            pass
        finally:
            conn.close()
            await tasks.drain()
            server.detach(conn)

    # ``max_size`` lifts the default 1 MiB frame cap: a loaded session history
    # or a large tool-argument blob can exceed it, and hitting the cap drops
    # the whole connection.  Loopback-only, so the larger ceiling is safe.
    async with websockets.serve(
        handler, BIND_HOST, port, ping_interval=20, max_size=16 * 1024 * 1024
    ):
        if on_listening is not None:
            on_listening(port)
        try:
            await stop
        except asyncio.CancelledError:
            pass
    return 0


__all__ = ["Connection", "serve_stdio", "serve_websocket", "decode"]

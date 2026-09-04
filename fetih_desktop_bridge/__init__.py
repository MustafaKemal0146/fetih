"""FETİH Masaüstü Köprüsü — Desktop Bridge.

A localhost-only JSON-RPC 2.0 transport that lets the native Windows shell
(``apps/windows/Fetih.Desktop``) drive the real Python agent.

NAMING CONTRACT (see ``docs/windows-app-plani.md`` §b):
    The word "gateway" is ALREADY TAKEN in this repo — it means the *messaging
    platform bridge* (``gateway/``: Telegram, Discord, WhatsApp, Slack ...).
    This package is a different thing: the UI transport layer.  Nothing in
    ``fetih_desktop_bridge/`` may use "gateway" for its own concepts.
    Env vars are ``FETIH_BRIDGE_*``, never ``FETIH_GATEWAY_*``.

Transports (identical dispatch, per ``server.dispatch``):
    * WebSocket — ``ws://127.0.0.1:<port>``, the default.
    * stdio     — NDJSON on stdin/stdout, for app-spawned child processes.

Entry points:
    fetih desktop-bridge                 # WebSocket on 127.0.0.1, random port
    fetih desktop-bridge --stdio         # NDJSON over stdio
    python -m fetih_desktop_bridge       # same, without the CLI wrapper
"""

from __future__ import annotations

#: Bumped whenever the RPC surface changes in a way clients must notice.
#: Reported by ``bridge.capabilities`` as ``protocol_version``.
PROTOCOL_VERSION = 1

#: Default WebSocket bind address.  NEVER make this configurable to a
#: non-loopback interface: this is a security tool and its own control
#: channel must not be reachable from the network.
BIND_HOST = "127.0.0.1"

__all__ = ["PROTOCOL_VERSION", "BIND_HOST"]

"""JSON-RPC 2.0 envelope helpers for the Masaüstü Köprüsü.

Wire format is line-delimited JSON (NDJSON): exactly one JSON object per
line, UTF-8, ``\\n`` terminated.  Both transports (stdio and WebSocket)
carry the identical frames, so a client written against one works against
the other unchanged.

Frame kinds
-----------
request       {"jsonrpc":"2.0","id":<int|str>,"method":"<name>","params":{...}}
response      {"jsonrpc":"2.0","id":<same>,"result":{...}}
error         {"jsonrpc":"2.0","id":<same>,"error":{"code":<int>,"message":"...","data":{...}}}
event         {"jsonrpc":"2.0","method":"<name>","params":{...}}   (no id — a notification)
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

JSONRPC = "2.0"

# --- Standard JSON-RPC codes ------------------------------------------------
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# --- FETİH bridge-specific codes (application range) ------------------------
UNAUTHORIZED = -32000      # no/invalid token
SESSION_NOT_FOUND = -32001
SESSION_BUSY = -32002      # a turn is already running on this session
AGENT_ERROR = -32003       # the agent ran but failed (provider 4xx/5xx, ...)
CONFIG_ERROR = -32004      # config.set rejected, managed install, ...
CANCELLED = -32005


def request(rid: Any, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"jsonrpc": JSONRPC, "id": rid, "method": method, "params": params or {}}


def response(rid: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": JSONRPC, "id": rid, "result": result}


def error(rid: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": JSONRPC, "id": rid, "error": err}


def event(method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A server→client notification (no ``id``, no reply expected)."""
    return {"jsonrpc": JSONRPC, "method": method, "params": params or {}}


def encode(frame: Dict[str, Any]) -> str:
    """Serialize one frame to a single NDJSON line (no trailing newline)."""
    return json.dumps(frame, ensure_ascii=False, default=str)


def decode(line: str) -> Dict[str, Any]:
    """Parse one NDJSON line. Raises ``ValueError`` on malformed input."""
    data = json.loads(line)
    if not isinstance(data, dict):
        raise ValueError("frame is not a JSON object")
    return data


class BridgeError(Exception):
    """Raised by RPC methods to produce a structured JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

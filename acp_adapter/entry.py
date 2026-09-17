"""Console entry point for the ``fetih-acp`` executable.

An ACP client (Zed, an IDE plugin) spawns this process and speaks JSON-RPC over
stdio, so **stdout carries the protocol and nothing else**.  Every human-facing
message in this module goes to stderr.
"""

try:
    import fetih_bootstrap  # noqa: F401
except ModuleNotFoundError:
    # Graceful fallback when the package is not yet registered in the venv —
    # happens during a partial update.  Missing bootstrap only means the
    # Windows UTF-8 stdio fix is skipped; POSIX is unaffected.
    pass

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import acp

logger = logging.getLogger(__name__)

# Probe methods some clients (and health checkers) send speculatively.  A
# JSON-RPC "method not found" for one of these is expected traffic, not a bug,
# so it must not be reported as a background task failure.
_BENIGN_PROBE_METHODS = frozenset({"ping", "health", "healthcheck"})

_BACKGROUND_TASK_MESSAGE = "Background task failed"

_JSONRPC_METHOD_NOT_FOUND = -32601


class _BenignProbeMethodFilter(logging.Filter):
    """Drop "Background task failed" records caused by an unknown ping.

    The ACP runtime reports every failed supervisor task with
    ``logging.exception("Background task failed", ...)``.  A client that probes
    ``ping``/``health`` before the handshake therefore produces a scary
    traceback on every connect.  Those records carry a
    :class:`~acp.exceptions.RequestError` with code ``-32601`` naming the
    probed method, which is how we tell them apart from a genuine failure.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.getMessage() != _BACKGROUND_TASK_MESSAGE:
            return True
        exc_info = record.exc_info
        if not exc_info:
            return True
        error = exc_info[1]
        if error is None or getattr(error, "code", None) != _JSONRPC_METHOD_NOT_FOUND:
            return True
        data = getattr(error, "data", None)
        method = data.get("method") if isinstance(data, dict) else None
        return method not in _BENIGN_PROBE_METHODS


def _setup_logging() -> None:
    """Send logs to stderr with the benign-probe filter installed."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.addFilter(_BenignProbeMethodFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        if isinstance(existing, logging.StreamHandler) and getattr(existing, "stream", None) is sys.stderr:
            root.removeHandler(existing)
    root.addHandler(handler)
    if root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)


def _load_env() -> None:
    """Load ``~/.fetih/.env`` and the project ``.env`` as a dev fallback."""
    try:
        from fetih_cli.env_loader import load_fetih_dotenv

        load_fetih_dotenv(project_env=Path(__file__).resolve().parent.parent / ".env")
    except Exception as exc:  # pragma: no cover - optional at runtime
        logger.debug("ACP environment files could not be loaded: %s", exc)


def _run_setup() -> int:
    """Run the interactive model/provider setup, then offer browser tools."""
    from fetih_cli import main as fetih_cli_main

    original_argv = sys.argv[:]
    entrypoint = original_argv[0] if original_argv else "fetih"
    sys.argv = [entrypoint, "model"]
    try:
        fetih_cli_main.main()
    finally:
        sys.argv = original_argv

    try:
        interactive = bool(sys.stdin.isatty())
    except Exception:
        interactive = False
    if not interactive:
        return 0

    try:
        answer = input("Install the browser tools too? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if isinstance(answer, str) and answer.strip().lower().startswith("y"):
        _run_setup_browser(assume_yes=False)
    return 0


def _run_setup_browser(assume_yes: bool = False) -> int:
    """Install the browser automation dependencies (node first)."""
    from fetih_cli import dep_ensure

    interactive = not assume_yes

    if not dep_ensure.ensure_dependency("node", interactive=interactive):
        print("Node.js is required for the browser tools and could not be installed.", file=sys.stderr)
        raise SystemExit(1)
    if not dep_ensure.ensure_dependency("browser", interactive=interactive):
        print("The browser tools could not be installed.", file=sys.stderr)
        raise SystemExit(1)
    print("Browser tools are ready.", file=sys.stderr)
    return 0


async def _serve() -> None:
    """Serve ACP over stdio until the client disconnects."""
    from acp_adapter.server import FETIHACPAgent

    await acp.run_agent(FETIHACPAgent(), use_unstable_protocol=True)


def main(argv: Optional[Any] = None) -> int:
    """Entry point for ``fetih-acp``."""
    args = list(argv) if argv is not None else sys.argv[1:]

    if "--version" in args:
        from acp_adapter import FETIH_VERSION

        print(f"fetih-acp {FETIH_VERSION}")
        return 0

    if "--check" in args:
        print("FETIH ACP check OK")
        return 0

    if "--setup-browser" in args:
        return _run_setup_browser(assume_yes="--yes" in args)

    if "--setup" in args:
        return _run_setup()

    from acp_adapter import FETIH_VERSION

    _setup_logging()
    _load_env()
    print(f"Starting fetih-agent ACP adapter {FETIH_VERSION}...", file=sys.stderr)
    asyncio.run(_serve())
    return 0


__all__ = ["_BenignProbeMethodFilter", "main"]


if __name__ == "__main__":  # pragma: no cover - module execution
    raise SystemExit(main())

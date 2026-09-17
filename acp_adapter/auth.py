"""Provider detection and ACP auth-method advertisement.

ACP clients show an auth picker when the agent has no credentials.  FETIH has
exactly two useful answers:

* an existing runtime provider, advertised so the client can "sign in" by
  simply acknowledging it; and
* a terminal escape hatch that runs ``fetih-acp --setup`` for a machine that
  has never been configured.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from acp.schema import AuthMethodAgent, TerminalAuthMethod

from fetih_cli import runtime_provider as runtime_provider_module

logger = logging.getLogger(__name__)

TERMINAL_SETUP_AUTH_METHOD_ID = "fetih-terminal-setup"

_TERMINAL_SETUP_DESCRIPTION = (
    "Open FETIH' interactive model/provider setup in a terminal. "
    "Use this when FETIH has not been configured on this machine yet."
)


def _resolve_runtime() -> Optional[dict]:
    """Resolve the current runtime provider config, or ``None`` on failure."""
    try:
        resolved = runtime_provider_module.resolve_runtime_provider()
    except Exception as exc:
        logger.debug("runtime provider resolution failed: %s", exc)
        return None
    if not isinstance(resolved, dict):
        return None
    return resolved


def has_provider() -> bool:
    """Return True when a usable provider + API key are configured."""
    resolved = _resolve_runtime()
    if not resolved:
        return False
    api_key = resolved.get("api_key")
    if not isinstance(api_key, str):
        return False
    return bool(api_key.strip())


def detect_provider() -> Optional[str]:
    """Return the normalized provider id, or ``None`` when unconfigured."""
    resolved = _resolve_runtime()
    if not resolved:
        return None
    api_key = resolved.get("api_key")
    if not isinstance(api_key, str) or not api_key.strip():
        return None
    provider = resolved.get("provider")
    if not isinstance(provider, str):
        return None
    provider = provider.strip().lower()
    return provider or None


def build_auth_methods() -> list:
    """Build the ACP auth methods for the current machine state."""
    methods: list[AuthMethod] = []
    provider = detect_provider()
    if provider:
        methods.append(
            AuthMethodAgent(id=provider, name=f"{provider} runtime credentials")
        )
    methods.append(
        TerminalAuthMethod(
            type="terminal",
            id=TERMINAL_SETUP_AUTH_METHOD_ID,
            name="Configure FETIH provider",
            description=_TERMINAL_SETUP_DESCRIPTION,
            args=["--setup"],
        )
    )
    return methods


def provider_label(provider: Optional[str]) -> str:
    """Human-readable label for a provider id."""
    if not provider:
        return "unconfigured"
    return str(provider)


__all__ = [
    "TERMINAL_SETUP_AUTH_METHOD_ID",
    "build_auth_methods",
    "detect_provider",
    "has_provider",
]

"""Slash confirm — gateway for dangerous-action confirmation prompts."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

_confirm_callback: Optional[Callable] = None


def set_confirm_callback(cb: Callable) -> None:
    global _confirm_callback
    _confirm_callback = cb


def request_confirmation(
    command: str,
    description: str = "",
    **kwargs: Any,
) -> str:
    """Ask for confirmation; returns 'approved' or 'denied'."""
    if _confirm_callback is not None:
        try:
            return _confirm_callback(command=command, description=description, **kwargs)
        except Exception as exc:
            logger.debug("confirm callback failed: %s", exc)
    return "denied"

"""Clarify gateway — routes clarification requests to the active UI."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_clarify_callback: Optional[Callable] = None


def set_clarify_callback(cb: Callable) -> None:
    global _clarify_callback
    _clarify_callback = cb


def clarify(
    question: str,
    choices: Optional[List[str]] = None,
    allow_freetext: bool = True,
    **kwargs: Any,
) -> str:
    """Present a clarification question; return the user's answer."""
    if _clarify_callback is not None:
        try:
            return _clarify_callback(question, choices=choices,
                                     allow_freetext=allow_freetext, **kwargs)
        except Exception as exc:
            logger.debug("clarify callback failed: %s", exc)
    # Non-interactive fallback
    return ""

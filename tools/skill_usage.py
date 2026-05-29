"""Skill usage tracking — stub module.

Records which skills were invoked and how often, for learning/analytics.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
_lock = threading.Lock()


def _log_path() -> Path:
    fetih_home = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))
    return Path(fetih_home) / "skill_usage.jsonl"


def record_skill_invocation(
    skill_name: str,
    trigger: Optional[str] = None,
    success: bool = True,
    **meta: Any,
) -> None:
    """Record a skill invocation to the usage log."""
    entry = {
        "skill": skill_name,
        "trigger": trigger,
        "success": success,
        **meta,
    }
    try:
        with _lock:
            path = _log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def get_skill_stats(skill_name: Optional[str] = None) -> Dict[str, Any]:
    """Return usage stats for one skill or all skills."""
    try:
        path = _log_path()
        if not path.exists():
            return {}
        counts: Dict[str, int] = {}
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    name = entry.get("skill", "unknown")
                    counts[name] = counts.get(name, 0) + 1
                except Exception:
                    pass
        if skill_name:
            return {"count": counts.get(skill_name, 0)}
        return counts
    except Exception:
        return {}

"""Self-improving agent: automatic learning capture, storage, and promotion.

When FETIH discovers something useful (a working technique, a bug workaround,
a tool quirk), it records the learning in ~/.fetih/learnings/. After 3
successful re-uses, the learning is promoted to the relevant SKILL.md.

Directory structure:
  ~/.fetih/learnings/
  ├── LEARNINGS.md        # All learnings, indexed by ID
  ├── ERRORS.md           # Error patterns and solutions
  ├── FEATURE_REQUESTS.md # User-requested features
  └── ctf/                # Challenge-specific learnings
      └── <challenge_hash>.md

Learning ID format: LRN-YYYYMMDD-NNN (auto-incrementing within day)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _learnings_dir() -> Path:
    """Return the learnings directory path."""
    fetih_home = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))
    return Path(fetih_home) / "learnings"


def _learnings_file() -> Path:
    return _learnings_dir() / "LEARNINGS.md"


def _errors_file() -> Path:
    return _learnings_dir() / "ERRORS.md"


def _features_file() -> Path:
    return _learnings_dir() / "FEATURE_REQUESTS.md"


def _stats_file() -> Path:
    return _learnings_dir() / ".stats.json"


# ---------------------------------------------------------------------------
# Learning entry
# ---------------------------------------------------------------------------

class LearningEntry:
    """A single learning record."""
    __slots__ = (
        "id", "timestamp", "priority", "status", "category",
        "trigger", "solution", "applied_count", "applied_sessions",
        "promoted_to", "tags",
    )

    def __init__(
        self,
        lid: str,
        timestamp: str = "",
        priority: str = "medium",
        status: str = "active",
        category: str = "general",
        trigger: str = "",
        solution: str = "",
        applied_count: int = 0,
        applied_sessions: List[str] = None,
        promoted_to: str = "",
        tags: List[str] = None,
    ):
        self.id = lid
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.priority = priority
        self.status = status
        self.category = category
        self.trigger = trigger
        self.solution = solution
        self.applied_count = applied_count
        self.applied_sessions = applied_sessions or []
        self.promoted_to = promoted_to
        self.tags = tags or []

    def to_markdown(self) -> str:
        lines = [
            f"### {self.id} | priority:{self.priority} | status:{self.status}",
            f"**Category:** {self.category}",
            f"**Tags:** {', '.join(self.tags)}" if self.tags else "**Tags:** -",
            f"**First seen:** {self.timestamp}",
            f"**Applied:** {self.applied_count}x (sessions: {', '.join(self.applied_sessions)})",
            f"**Trigger:** {self.trigger}",
            f"**Solution:** {self.solution}",
        ]
        if self.promoted_to:
            lines.append(f"**Promoted to:** {self.promoted_to}")
        lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "priority": self.priority,
            "status": self.status,
            "category": self.category,
            "trigger": self.trigger,
            "solution": self.solution,
            "applied_count": self.applied_count,
            "applied_sessions": self.applied_sessions,
            "promoted_to": self.promoted_to,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def _ensure_dirs() -> None:
    """Ensure learnings directories exist."""
    base = _learnings_dir()
    base.mkdir(parents=True, exist_ok=True)
    (base / "ctf").mkdir(parents=True, exist_ok=True)

    for path in [_learnings_file(), _errors_file(), _features_file()]:
        if not path.exists():
            path.write_text(
                f"# FETIH Learnings\n\n"
                f"Auto-generated knowledge base. Entries are created automatically\n"
                f"when FETIH discovers reusable techniques, patterns, or solutions.\n\n"
                f"---\n\n",
                encoding="utf-8",
            )


def _generate_id() -> str:
    """Generate a new learning ID."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    _ensure_dirs()

    # Find existing IDs for today
    existing = _load_stats().get("last_ids", [])
    today_prefix = f"LRN-{today}-"
    today_ids = [lid for lid in existing if lid.startswith(today_prefix)]

    if today_ids:
        nums = []
        for tid in today_ids:
            try:
                nums.append(int(tid.split("-")[-1]))
            except (ValueError, IndexError):
                pass
        next_num = max(nums) + 1 if nums else 1
    else:
        next_num = 1

    return f"LRN-{today}-{next_num:03d}"


def _load_stats() -> Dict[str, Any]:
    """Load learning statistics."""
    try:
        if _stats_file().exists():
            return json.loads(_stats_file().read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_stats(stats: Dict[str, Any]) -> None:
    """Save learning statistics."""
    _ensure_dirs()
    try:
        _stats_file().write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save learning stats: %s", e)


def _parse_learnings_file() -> List[LearningEntry]:
    """Parse all learning entries from LEARNINGS.md."""
    _ensure_dirs()
    entries: List[LearningEntry] = []
    try:
        content = _learnings_file().read_text(encoding="utf-8")
    except Exception:
        return entries

    # Parse each ### block
    blocks = re.split(r'\n(?=### )', content)

    for block in blocks:
        if not block.startswith("### "):
            continue

        lines = block.strip().split("\n")
        header = lines[0] if lines else ""
        body = "\n".join(lines[1:])

        # Parse header: ### LRN-20260529-001 | priority:high | status:active
        h_match = re.match(r'###\s+(LRN-\d{8}-\d{3})\s*\|\s*priority:(\w+)\s*\|\s*status:(\w+)', header)
        if not h_match:
            continue

        lid = h_match.group(1)
        priority = h_match.group(2)
        status = h_match.group(3)

        # Parse body fields
        def _extract(pattern: str, text: str, default: str = "") -> str:
            m = re.search(pattern, text)
            return m.group(1).strip() if m else default

        category = _extract(r'\*\*Category:\*\*\s*(.+)', body, "general")
        trigger = _extract(r'\*\*Trigger:\*\*\s*(.+)', body, "")
        solution = _extract(r'\*\*Solution:\*\*\s*(.+)', body, "")
        promoted = _extract(r'\*\*Promoted to:\*\*\s*(.+)', body, "")

        applied_str = _extract(r'\*\*Applied:\*\*\s*(.+)', body, "0x")
        try:
            applied_count = int(re.search(r'(\d+)x', applied_str).group(1))
        except (AttributeError, ValueError):
            applied_count = 0

        # Tags
        tags_str = _extract(r'\*\*Tags:\*\*\s*(.+)', body, "")
        tags = [t.strip() for t in tags_str.split(",") if t.strip() and t.strip() != "-"]

        entries.append(LearningEntry(
            lid=lid, priority=priority, status=status,
            category=category, trigger=trigger, solution=solution,
            applied_count=applied_count, promoted_to=promoted, tags=tags,
        ))

    return entries


def record_learning(
    trigger: str,
    solution: str,
    category: str = "general",
    priority: str = "medium",
    tags: List[str] = None,
    session_id: str = "",
) -> Optional[str]:
    """Record a new learning. Returns the learning ID, or None on failure."""
    _ensure_dirs()

    # Check for duplicates — similar trigger text
    existing = _parse_learnings_file()
    trigger_lower = trigger.lower().strip()
    for entry in existing:
        if entry.trigger.lower().strip()[:60] == trigger_lower[:60]:
            # Increment usage count
            _increment_usage(entry.id, session_id)
            return entry.id

    lid = _generate_id()
    entry = LearningEntry(
        lid=lid,
        priority=priority,
        category=category,
        trigger=trigger,
        solution=solution,
        applied_count=1,
        applied_sessions=[session_id] if session_id else [],
        tags=tags or [],
    )

    try:
        md_block = entry.to_markdown()
        with open(_learnings_file(), "a", encoding="utf-8") as f:
            f.write(md_block)

        # Update stats
        stats = _load_stats()
        stats.setdefault("total_learnings", 0)
        stats["total_learnings"] += 1
        stats.setdefault("last_ids", [])
        stats["last_ids"].append(lid)
        if len(stats["last_ids"]) > 100:
            stats["last_ids"] = stats["last_ids"][-100:]
        _save_stats(stats)

        logger.info("Recorded learning %s: %s", lid, trigger[:80])
        return lid
    except Exception as e:
        logger.warning("Failed to record learning: %s", e)
        return None


def record_error(
    error_message: str,
    context: str = "",
    solution: str = "",
    session_id: str = "",
) -> None:
    """Record an error pattern and its solution."""
    _ensure_dirs()
    try:
        ts = datetime.now(timezone.utc).isoformat()
        block = (
            f"### ERR-{ts[:10]}\n"
            f"**When:** {ts}\n"
            f"**Error:** {error_message[:300]}\n"
            f"**Context:** {context[:200]}\n"
            f"**Solution:** {solution[:300] or 'TBD'}\n"
            f"**Session:** {session_id}\n\n"
        )
        with open(_errors_file(), "a", encoding="utf-8") as f:
            f.write(block)
    except Exception as e:
        logger.warning("Failed to record error: %s", e)


def record_feature_request(
    description: str,
    priority: str = "medium",
    session_id: str = "",
) -> None:
    """Record a user feature request."""
    _ensure_dirs()
    try:
        ts = datetime.now(timezone.utc).isoformat()
        block = (
            f"### FR-{ts[:10]}\n"
            f"**When:** {ts}\n"
            f"**Priority:** {priority}\n"
            f"**Description:** {description[:500]}\n"
            f"**Session:** {session_id}\n\n"
        )
        with open(_features_file(), "a", encoding="utf-8") as f:
            f.write(block)
    except Exception as e:
        logger.warning("Failed to record feature request: %s", e)


def _increment_usage(learning_id: str, session_id: str = "") -> None:
    """Increment the usage counter for an existing learning."""
    _ensure_dirs()
    try:
        content = _learnings_file().read_text(encoding="utf-8")
        # Find the block and update applied count
        pattern = rf'(### {re.escape(learning_id)}.*?)(\*\*Applied:\*\*\s*)(\d+)(x)'
        def _replacer(m):
            count = int(m.group(3)) + 1
            return f"{m.group(1)}{m.group(2)}{count}{m.group(4)}"
        new_content = re.sub(pattern, _replacer, content, count=1)

        if new_content != content:
            _learnings_file().write_text(new_content, encoding="utf-8")

            # Check if promotion threshold reached (3+ uses)
            if int(re.search(pattern, new_content).group(3)) >= 3:
                _promote_learning(learning_id)

    except Exception as e:
        logger.warning("Failed to increment usage for %s: %s", learning_id, e)


def _promote_learning(learning_id: str) -> None:
    """Promote a learning to the relevant SKILL.md after threshold.

    Promotion appends a ### Historical Learnings section to the most
    relevant SKILL.md based on the learning's category and tags.
    """
    entries = _parse_learnings_file()
    entry = next((e for e in entries if e.id == learning_id), None)
    if not entry or entry.promoted_to:
        return

    # Find the best SKILL.md to promote to
    skills_dir = Path(os.environ.get(
        "FETIH_SKILLS_DIR",
        str(Path(__file__).resolve().parent.parent / "skills")
    ))

    # Simple matching: find SKILL.md with matching category
    target_skill = None
    if entry.category:
        for skill_path in skills_dir.glob(f"**/{entry.category}*/SKILL.md"):
            target_skill = skill_path
            break

    if target_skill is None:
        # Fall back to general cybersecurity skill
        for skill_path in skills_dir.glob("**/cybersecurity/SKILL.md"):
            target_skill = skill_path
            break

    if target_skill is None:
        return

    try:
        skill_content = target_skill.read_text(encoding="utf-8")

        # Add Historical Learnings section if not present
        if "## Historical Learnings" not in skill_content:
            skill_content += "\n\n## Historical Learnings\n\n"

        # Append the learning
        learning_block = (
            f"- **{entry.id}** ({entry.priority}): {entry.trigger[:120]} "
            f"→ {entry.solution[:120]}\n"
        )
        skill_content += learning_block
        target_skill.write_text(skill_content, encoding="utf-8")

        # Mark as promoted
        _mark_promoted(learning_id, str(target_skill))
        logger.info("Promoted %s to %s", learning_id, target_skill)
    except Exception as e:
        logger.warning("Failed to promote %s: %s", learning_id, e)


def _mark_promoted(learning_id: str, target_path: str) -> None:
    """Mark a learning as promoted in LEARNINGS.md."""
    try:
        content = _learnings_file().read_text(encoding="utf-8")
        pattern = rf'(### {re.escape(learning_id)} .*)'
        new_content = re.sub(
            pattern,
            rf'\1\n**Promoted to:** {target_path}',
            content,
            count=1,
        )
        _learnings_file().write_text(new_content, encoding="utf-8")
    except Exception:
        pass


def list_learnings(
    category: str = "",
    priority: str = "",
    status: str = "active",
    limit: int = 50,
) -> List[LearningEntry]:
    """List learnings with optional filters."""
    entries = _parse_learnings_file()
    result = []
    for e in entries:
        if category and e.category != category:
            continue
        if priority and e.priority != priority:
            continue
        if status and e.status != status:
            continue
        result.append(e)
    return result[-limit:]


def search_learnings(query: str, limit: int = 20) -> List[LearningEntry]:
    """Search learnings by keyword (searches trigger + solution)."""
    entries = _parse_learnings_file()
    q = query.lower()
    scored = []
    for e in entries:
        score = 0
        if q in e.trigger.lower():
            score += 3
        if q in e.solution.lower():
            score += 2
        if q in " ".join(e.tags).lower():
            score += 1
        if score > 0:
            scored.append((score, e))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:limit]]


def get_learning_stats() -> Dict[str, Any]:
    """Return learning statistics."""
    entries = _parse_learnings_file()
    stats = _load_stats()
    by_category = defaultdict(int)
    by_priority = defaultdict(int)
    by_status = defaultdict(int)

    for e in entries:
        by_category[e.category] += 1
        by_priority[e.priority] += 1
        by_status[e.status] += 1

    return {
        "total": len(entries),
        "tracked": stats.get("total_learnings", 0),
        "promoted": sum(1 for e in entries if e.promoted_to),
        "by_category": dict(by_category),
        "by_priority": dict(by_priority),
        "by_status": dict(by_status),
        "last_id": stats.get("last_ids", [])[-1] if stats.get("last_ids") else None,
    }


def inject_learnings_prompt(max_learnings: int = 10) -> str:
    """Build a prompt snippet with the most relevant recent learnings.

    Intended to be appended to the system prompt so the agent remembers
    previously discovered techniques.
    """
    entries = _parse_learnings_file()
    # Prioritize: high priority active first, then recent
    active = [e for e in entries if e.status == "active"]
    active.sort(
        key=lambda e: (
            0 if e.priority == "high" else 1 if e.priority == "medium" else 2,
            e.timestamp,
        ),
    )

    if not active:
        return ""

    lines = ["\n## 🧠 Historical Learnings (from past sessions)\n"]
    lines.append("These techniques were discovered in previous FETIH sessions "
                 "and may be useful:")
    lines.append("")

    for e in active[:max_learnings]:
        lines.append(f"- **{e.id}** [{e.priority}] {e.trigger[:100]}")
        lines.append(f"  Solution: {e.solution[:150]}")

    return "\n".join(lines)

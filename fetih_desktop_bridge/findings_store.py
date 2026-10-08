"""Persistent findings store for the desktop bridge (issue #33).

Findings used to live in an in-memory list on ``BridgeServer`` and vanished
when the app closed. They now go to a small SQLite database next to the
session store, so an operation's results survive restarts.

Findings are tagged with the session that produced them (for filtering) but
live in their own database file: deleting a chat does not erase what was
found during it. Identical findings are de-duplicated by a fingerprint so
re-running a scan does not multiply rows.
"""

from __future__ import annotations

import hashlib
import unicodedata
import logging
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Canonical severities, most severe first. Sorting uses this order.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_SEVERITY_ALIASES = {
    "critical": "Critical", "kritik": "Critical",
    "high": "High", "yüksek": "High", "yuksek": "High",
    "medium": "Medium", "moderate": "Medium", "orta": "Medium",
    "low": "Low", "düşük": "Low", "dusuk": "Low",
    "info": "Info", "informational": "Info", "bilgi": "Info",
}

_FIELDS = ("title", "target", "severity", "evidence", "recommendation", "reference")


def normalize_severity(value: Any) -> str:
    """Map free-form severity text onto the canonical set (unknown → Info)."""
    key = str(value or "").strip().lower()
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key]
    # Türkçe "İ" küçültmesi "i̇" (birleşik nokta) üretir; aksan/combining
    # işaretleri soyarak bir kez daha dene.
    folded = "".join(
        c for c in unicodedata.normalize("NFKD", key) if not unicodedata.combining(c)
    )
    return _SEVERITY_ALIASES.get(folded, "Info")


def _fingerprint(session_id: str, finding: Dict[str, Any]) -> str:
    parts = [session_id or ""] + [str(finding.get(f) or "") for f in ("severity", "title", "target", "evidence")]
    return hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()


class FindingsStore:
    """Thread-safe SQLite store; every statement runs under ``_lock``."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error as exc:
            logger.warning("findings store pragma failed: %s", exc)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings(
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                target TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'Info',
                evidence TEXT NOT NULL DEFAULT '',
                recommendation TEXT NOT NULL DEFAULT '',
                reference TEXT NOT NULL DEFAULT '',
                discovered_at TEXT NOT NULL DEFAULT '',
                created REAL NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS ix_findings_session ON findings(session_id);
            """
        )
        self.db.commit()

    # ── writes ────────────────────────────────────────────────────────────

    def add(self, finding: Dict[str, Any], session_id: str = "") -> Optional[Dict[str, Any]]:
        """Store a finding. Returns the stored row, or ``None`` if it is a duplicate."""
        row = {f: str(finding.get(f) or "") for f in _FIELDS}
        row["severity"] = normalize_severity(finding.get("severity"))
        row["id"] = str(finding.get("id") or uuid.uuid4().hex[:8])
        row["session_id"] = str(session_id or finding.get("session_id") or "")
        row["discovered_at"] = str(
            finding.get("discovered_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )
        fp = _fingerprint(row["session_id"], row)
        with self._lock:
            try:
                self.db.execute(
                    "INSERT INTO findings(id, session_id, title, target, severity, evidence,"
                    " recommendation, reference, discovered_at, created, fingerprint)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        row["id"], row["session_id"], row["title"], row["target"],
                        row["severity"], row["evidence"], row["recommendation"],
                        row["reference"], row["discovered_at"], time.time(), fp,
                    ),
                )
                self.db.commit()
            except sqlite3.IntegrityError:
                return None  # same finding already recorded
        return row

    def delete(self, finding_id: str) -> bool:
        with self._lock:
            cur = self.db.execute("DELETE FROM findings WHERE id=?", (str(finding_id),))
            self.db.commit()
            return cur.rowcount > 0

    def clear(self, session_id: Optional[str] = None) -> int:
        with self._lock:
            if session_id:
                cur = self.db.execute("DELETE FROM findings WHERE session_id=?", (session_id,))
            else:
                cur = self.db.execute("DELETE FROM findings")
            self.db.commit()
            return cur.rowcount

    # ── reads ─────────────────────────────────────────────────────────────

    def count(self) -> int:
        with self._lock:
            return int(self.db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])

    def list(
        self,
        *,
        severity: Optional[str] = None,
        session_id: Optional[str] = None,
        query: Optional[str] = None,
        sort: str = "severity",
    ) -> List[Dict[str, Any]]:
        """Filtered findings. ``sort``: ``severity`` (most severe first) or ``time`` (newest first)."""
        sql = "SELECT * FROM findings WHERE 1=1"
        args: List[Any] = []
        if severity:
            sql += " AND severity=?"
            args.append(normalize_severity(severity))
        if session_id:
            sql += " AND session_id=?"
            args.append(session_id)
        if query:
            like = f"%{query.strip()}%"
            sql += " AND (title LIKE ? OR target LIKE ? OR evidence LIKE ? OR reference LIKE ?)"
            args += [like, like, like, like]
        sql = sql.replace("SELECT * FROM findings", "SELECT rowid AS _rid, * FROM findings", 1)
        with self._lock:
            rows = [dict(r) for r in self.db.execute(sql, args).fetchall()]
        # rowid: ekleme sırası = monotonik; eşit `created` (Windows'un düşük
        # saat çözünürlüğü) durumunda kararlı tiebreak.
        for r in rows:
            r.pop("fingerprint", None)
        rids = {id(r): r.pop("_rid", 0) for r in rows}
        if sort == "time":
            rows.sort(key=lambda r: rids[id(r)], reverse=True)
        else:
            rows.sort(key=lambda r: (_SEVERITY_RANK.get(r.get("severity"), 99), -rids[id(r)]))
        return rows

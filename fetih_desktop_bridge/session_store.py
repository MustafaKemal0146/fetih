import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SessionStore:
    """SQLite-backed persistent storage for desktop chat sessions and transcript items.

    Concurrency: the bridge now dispatches requests concurrently and the agent
    runs on worker threads, so the single ``check_same_thread=False`` connection
    is reached from several threads at once (agent thread, ThoughtLabeler
    thread, event loop).  Every access is serialized through ``_lock`` to avoid
    interleaved statements and ``sqlite3.ProgrammingError``/``database is
    locked`` races.
    """

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        # WAL + synchronous=NORMAL: her tur onlarca append() (text flush, her
        # tool_call/tool_result) ayrı commit yapar. WAL okuyucuyu yazardan
        # ayırır ve fsync maliyetini düşürür; loopback/tek-kullanıcı deposu
        # için NORMAL dayanıklılık yeterli. En iyi çaba — bazı dosya
        # sistemlerinde (ağ sürücüsü) WAL reddedilebilir, o yüzden sarmalı.
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error as exc:
            logger.warning("WAL/synchronous pragma uygulanamadı: %s", exc)
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS sessions(
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            created_at REAL,
            updated_at REAL
        );
        CREATE TABLE IF NOT EXISTS items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            ts REAL
        );
        CREATE INDEX IF NOT EXISTS ix_items_session ON items(session_id, id);
        """)

    def create(self, sid: Optional[str] = None, title: str = "") -> str:
        sid = sid or uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO sessions(id, title, created_at, updated_at) VALUES(?,?,?,?)",
                (sid, title, now, now),
            )
            self.db.commit()
        return sid

    def exists(self, sid: str) -> bool:
        with self._lock:
            r = self.db.execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone()
        return r is not None

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT id, title, updated_at FROM sessions ORDER BY updated_at DESC"
            ).fetchall()
        return [
            {
                "session_id": r["id"],
                "title": r["title"] or "Yeni sohbet",
                "updated_at": float(r["updated_at"] or 0.0),
            }
            for r in rows
        ]

    def title(self, sid: str) -> str:
        with self._lock:
            r = self.db.execute("SELECT title FROM sessions WHERE id=?", (sid,)).fetchone()
        return r["title"] if r else ""

    def rename(self, sid: str, title: str) -> None:
        with self._lock:
            self.db.execute("UPDATE sessions SET title=?, updated_at=? WHERE id=?", (title, time.time(), sid))
            self.db.commit()

    def append(self, sid: str, kind: str, payload: Dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            # Ensure session exists
            if not self._exists_locked(sid):
                self._create_locked(sid=sid)
            self.db.execute(
                "INSERT INTO items(session_id, kind, payload, ts) VALUES(?,?,?,?)",
                (sid, kind, json.dumps(payload, ensure_ascii=False), now),
            )
            self.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (now, sid))
            self.db.commit()

    def _exists_locked(self, sid: str) -> bool:
        r = self.db.execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone()
        return r is not None

    def _create_locked(self, sid: Optional[str] = None, title: str = "") -> str:
        sid = sid or uuid.uuid4().hex
        now = time.time()
        self.db.execute(
            "INSERT OR REPLACE INTO sessions(id, title, created_at, updated_at) VALUES(?,?,?,?)",
            (sid, title, now, now),
        )
        self.db.commit()
        return sid

    def items(self, sid: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT kind, payload FROM items WHERE session_id=? ORDER BY id ASC", (sid,)
            ).fetchall()
        result: List[Dict[str, Any]] = []
        for r in rows:
            try:
                data = json.loads(r["payload"])
                result.append({"kind": r["kind"], **data})
            except Exception as e:
                logger.warning("Failed to parse item payload: %s", e)
        return result

    def update_last_thought_label(self, sid: str, label: str) -> None:
        if not label:
            return
        with self._lock:
            row = self.db.execute(
                "SELECT id, payload FROM items WHERE session_id=? AND kind='thought' ORDER BY id DESC LIMIT 1",
                (sid,),
            ).fetchone()
            if row:
                try:
                    data = json.loads(row["payload"])
                    data["label"] = label
                    self.db.execute(
                        "UPDATE items SET payload=? WHERE id=?",
                        (json.dumps(data, ensure_ascii=False), row["id"]),
                    )
                    self.db.commit()
                except Exception as e:
                    logger.warning("Failed to update thought label: %s", e)

    def delete(self, sid: str) -> None:
        with self._lock:
            self.db.execute("DELETE FROM sessions WHERE id=?", (sid,))
            self.db.commit()

    def delete_all(self) -> None:
        with self._lock:
            self.db.execute("DELETE FROM sessions")
            self.db.commit()


class TranscriptRecorder:
    """Buffers stream deltas and records discrete turn items to the SessionStore."""

    def __init__(self, store: SessionStore, sid: str):
        self.store = store
        self.sid = sid
        self.kind: Optional[str] = None
        self.buf: List[str] = []
        self.t0: Dict[str, float] = {}
        self.kind_start: Optional[float] = None
        self.current_thought_label: Optional[str] = None

    def set_thought_label(self, label: str) -> None:
        if not label:
            return
        self.current_thought_label = label
        self.store.update_last_thought_label(self.sid, label)

    def snapshot(self) -> Optional[Dict[str, Any]]:
        if self.kind and self.buf:
            text_val = "".join(self.buf)
            if text_val:
                payload: Dict[str, Any] = {"text": text_val, "in_flight": True}
                if self.kind == "thought":
                    if self.kind_start is not None:
                        payload["ts_start"] = self.kind_start
                    if self.current_thought_label:
                        payload["label"] = self.current_thought_label
                return {"kind": self.kind, **payload}
        return None

    def text(self, kind: str, chunk: str) -> None:
        if not chunk:
            return
        if self.kind != kind:
            self.flush()
            self.kind = kind
            self.kind_start = time.time()
        self.buf.append(chunk)

    def flush(self) -> None:
        if self.kind and self.buf:
            text_val = "".join(self.buf)
            if text_val:
                payload: Dict[str, Any] = {"text": text_val}
                if self.kind == "thought":
                    if self.kind_start is not None:
                        now = time.time()
                        payload["ts_start"] = self.kind_start
                        payload["ts_end"] = now
                        payload["duration_ms"] = int((now - self.kind_start) * 1000)
                    if self.current_thought_label:
                        payload["label"] = self.current_thought_label
                self.store.append(self.sid, self.kind, payload)
        self.kind = None
        self.buf = []
        self.kind_start = None
        self.current_thought_label = None

    def tool_call(self, call_id: str, name: str, args: Any) -> None:
        self.flush()
        self.t0[str(call_id)] = time.time()
        self.store.append(
            self.sid,
            "tool_call",
            {"call_id": str(call_id), "name": name, "args": args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)},
        )

    def tool_result(self, call_id: str, result: Any) -> None:
        start = self.t0.pop(str(call_id), time.time())
        duration_ms = int((time.time() - start) * 1000)
        self.store.append(
            self.sid,
            "tool_result",
            {"call_id": str(call_id), "result": result if isinstance(result, str) else json.dumps(result, ensure_ascii=False), "duration_ms": duration_ms},
        )

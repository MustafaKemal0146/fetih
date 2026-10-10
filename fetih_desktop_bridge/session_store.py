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
            updated_at REAL,
            pinned INTEGER NOT NULL DEFAULT 0
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
        try:
            self.db.execute("ALTER TABLE sessions ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
            self.db.commit()
        except sqlite3.OperationalError:
            pass

    def create(self, sid: Optional[str] = None, title: str = "", pinned: bool = False) -> str:
        sid = sid or uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO sessions(id, title, created_at, updated_at, pinned) VALUES(?,?,?,?,?)",
                (sid, title, now, now, 1 if pinned else 0),
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
                "SELECT id, title, updated_at, pinned FROM sessions ORDER BY updated_at DESC"
            ).fetchall()
        return [
            {
                "session_id": r["id"],
                "title": r["title"] or "Yeni sohbet",
                "updated_at": float(r["updated_at"] or 0.0),
                "pinned": bool(r["pinned"] if "pinned" in r.keys() else 0),
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

    def _create_locked(self, sid: Optional[str] = None, title: str = "", pinned: bool = False) -> str:
        sid = sid or uuid.uuid4().hex
        now = time.time()
        self.db.execute(
            "INSERT OR REPLACE INTO sessions(id, title, created_at, updated_at, pinned) VALUES(?,?,?,?,?)",
            (sid, title, now, now, 1 if pinned else 0),
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

    def set_pinned(self, sid: str, pinned: bool) -> None:
        with self._lock:
            self.db.execute("UPDATE sessions SET pinned=? WHERE id=?", (1 if pinned else 0, sid))
            self.db.commit()

    def is_pinned(self, sid: str) -> bool:
        with self._lock:
            r = self.db.execute("SELECT pinned FROM sessions WHERE id=?", (sid,)).fetchone()
            return bool(r["pinned"]) if r and "pinned" in r.keys() else False

    def prune_by_age(self, retention_days: int, active_session_ids: Optional[Any] = None) -> int:
        """Deletes unpinned non-active sessions older than retention_days.
        Returns the number of deleted sessions.
        """
        cutoff = time.time() - (retention_days * 86400)
        active_set = set(active_session_ids or [])
        deleted = 0
        with self._lock:
            rows = self.db.execute(
                "SELECT id, updated_at, pinned FROM sessions WHERE updated_at < ?", (cutoff,)
            ).fetchall()
            for r in rows:
                sid = r["id"]
                is_pin = bool(r["pinned"]) if "pinned" in r.keys() else False
                if is_pin or sid in active_set:
                    continue
                self.db.execute("DELETE FROM sessions WHERE id=?", (sid,))
                deleted += 1
            if deleted > 0:
                self.db.commit()
        return deleted

    def _get_db_size_bytes(self) -> int:
        if self.path and self.path != ":memory:" and os.path.exists(self.path):
            size = os.path.getsize(self.path)
            wal_path = self.path + "-wal"
            if os.path.exists(wal_path):
                size += os.path.getsize(wal_path)
            return size
        try:
            page_count = self.db.execute("PRAGMA page_count").fetchone()[0]
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            return page_count * page_size
        except Exception:
            return 0

    def enforce_size_cap(self, max_db_mb: int, active_session_ids: Optional[Any] = None) -> Dict[str, Any]:
        """Deletes oldest unpinned non-active sessions until DB is under max_db_mb, and runs VACUUM.
        Returns a dict with statistics: {"deleted_sessions": N, "freed_mb": M, "final_size_mb": K}.
        """
        active_set = set(active_session_ids or [])
        initial_bytes = self._get_db_size_bytes()
        max_bytes = max_db_mb * 1024 * 1024
        deleted = 0

        with self._lock:
            curr_bytes = self._get_db_size_bytes()
            if curr_bytes > max_bytes:
                rows = self.db.execute(
                    "SELECT id, pinned FROM sessions ORDER BY updated_at ASC"
                ).fetchall()
                for r in rows:
                    sid = r["id"]
                    is_pin = bool(r["pinned"]) if "pinned" in r.keys() else False
                    if is_pin or sid in active_set:
                        continue
                    self.db.execute("DELETE FROM sessions WHERE id=?", (sid,))
                    self.db.commit()
                    deleted += 1
                    try:
                        self.db.execute("VACUUM")
                    except Exception:
                        pass
                    if self._get_db_size_bytes() <= max_bytes:
                        break
            else:
                try:
                    self.db.execute("VACUUM")
                except Exception:
                    pass

            final_bytes = self._get_db_size_bytes()

        freed_mb = max(0.0, (initial_bytes - final_bytes) / (1024 * 1024))
        final_mb = final_bytes / (1024 * 1024)
        return {
            "deleted_sessions": deleted,
            "freed_mb": round(freed_mb, 2),
            "final_size_mb": round(final_mb, 2),
        }


class TranscriptRecorder:
    """Buffers stream deltas and records discrete turn items to the SessionStore."""

    def __init__(self, store: SessionStore, sid: str, max_tool_result_chars: Optional[int] = None):
        self.store = store
        self.sid = sid
        self.kind: Optional[str] = None
        self.buf: List[str] = []
        self.t0: Dict[str, float] = {}
        self.kind_start: Optional[float] = None
        self.current_thought_label: Optional[str] = None
        if max_tool_result_chars is not None:
            self.max_tool_result_chars = int(max_tool_result_chars)
        else:
            try:
                from fetih_cli.config import load_config
                cfg = load_config()
                desktop_cfg = cfg.get("desktop") or {}
                store_cfg = desktop_cfg.get("store") or {}
                self.max_tool_result_chars = int(store_cfg.get("max_tool_result_chars", 20000))
            except Exception:
                self.max_tool_result_chars = 20000

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
        res_str = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        if len(res_str) > self.max_tool_result_chars:
            half = self.max_tool_result_chars // 2
            cut_count = len(res_str) - (half * 2)
            res_str = f"{res_str[:half]}\n... [{cut_count} karakter kesildi]\n{res_str[-half:]}"
        self.store.append(
            self.sid,
            "tool_result",
            {"call_id": str(call_id), "result": res_str, "duration_ms": duration_ms},
        )

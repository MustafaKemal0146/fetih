"""Unit and integration tests for session store cleanup and limits (Issue #74).

Tests:
  - TranscriptRecorder.tool_result truncates large outputs (> max_tool_result_chars)
  - Head + tail kept with '... [<N> karakter kesildi]' marker
  - Small results (< max_tool_result_chars) are untouched
  - SessionStore pinned status (create, set_pinned, is_pinned, list)
  - SessionStore.prune_by_age deletes unpinned non-active sessions older than retention_days
  - SessionStore.enforce_size_cap deletes oldest sessions until under cap & VACUUM
  - Bridge system.store_cleanup RPC method
"""

import os
import time
import pytest
from unittest.mock import MagicMock

from fetih_desktop_bridge.session_store import SessionStore, TranscriptRecorder
from fetih_desktop_bridge.server import BridgeServer


@pytest.fixture
def store(tmp_path):
    db_file = str(tmp_path / "sessions.db")
    return SessionStore(db_file)


class TestTranscriptRecorderTruncation:
    def test_tool_result_truncation(self, store):
        rec = TranscriptRecorder(store, "s1", max_tool_result_chars=100)
        large_output = "A" * 60 + "B" * 60  # 120 chars > 100

        rec.tool_result("call_1", large_output)

        items = store.items("s1")
        assert len(items) == 1
        res = items[0]["result"]

        # Expected: half (50) + marker (20 cut) + half (50)
        assert len(res) < 140
        assert "... [20 karakter kesildi]" in res
        assert res.startswith("A" * 50)
        assert res.endswith("B" * 50)

    def test_tool_result_no_truncation_when_under_limit(self, store):
        rec = TranscriptRecorder(store, "s2", max_tool_result_chars=1000)
        output = "Small output text"
        rec.tool_result("call_2", output)

        items = store.items("s2")
        assert len(items) == 1
        assert items[0]["result"] == output

    def test_tool_result_default_limit(self, store):
        rec = TranscriptRecorder(store, "s3")
        assert rec.max_tool_result_chars == 20000


class TestSessionStorePinningAndPruning:
    def test_pinning_functionality(self, store):
        sid1 = store.create(title="Normal Session", pinned=False)
        sid2 = store.create(title="Pinned Session", pinned=True)

        assert store.is_pinned(sid1) is False
        assert store.is_pinned(sid2) is True

        store.set_pinned(sid1, True)
        assert store.is_pinned(sid1) is True

        store.set_pinned(sid2, False)
        assert store.is_pinned(sid2) is False

        sessions = store.list()
        s_map = {s["session_id"]: s for s in sessions}
        assert s_map[sid1]["pinned"] is True
        assert s_map[sid2]["pinned"] is False

    def test_prune_by_age(self, store):
        now = time.time()
        old_ts = now - (40 * 86400)  # 40 days ago
        recent_ts = now - (5 * 86400)  # 5 days ago

        # 1. Old unpinned session (should be deleted)
        s_old = store.create(title="Old Unpinned")
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (old_ts, s_old))

        # 2. Old pinned session (should NOT be deleted)
        s_pinned = store.create(title="Old Pinned", pinned=True)
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (old_ts, s_pinned))

        # 3. Old active session (should NOT be deleted when in active_ids)
        s_active = store.create(title="Old Active")
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (old_ts, s_active))

        # 4. Recent session (should NOT be deleted)
        s_recent = store.create(title="Recent")
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (recent_ts, s_recent))
        store.db.commit()

        # Prune older than 30 days
        deleted = store.prune_by_age(retention_days=30, active_session_ids={s_active})
        assert deleted == 1

        assert store.exists(s_old) is False
        assert store.exists(s_pinned) is True
        assert store.exists(s_active) is True
        assert store.exists(s_recent) is True

    def test_enforce_size_cap(self, store):
        # Create 3 sessions with items
        s1 = store.create(title="Oldest")
        store.append(s1, "assistant", {"text": "A" * 1000})
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (100.0, s1))

        s2 = store.create(title="Middle", pinned=True)
        store.append(s2, "assistant", {"text": "B" * 1000})
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (200.0, s2))

        s3 = store.create(title="Newest")
        store.append(s3, "assistant", {"text": "C" * 1000})
        store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (300.0, s3))
        store.db.commit()

        # Enforce size cap with 0 MB to trigger cleanup of oldest unpinned sessions
        res = store.enforce_size_cap(max_db_mb=0, active_session_ids={s3})
        # s1 should be deleted (oldest unpinned non-active)
        # s2 is pinned -> kept
        # s3 is active -> kept
        assert res["deleted_sessions"] == 1
        assert store.exists(s1) is False
        assert store.exists(s2) is True
        assert store.exists(s3) is True


class TestBridgeSystemStoreCleanupRPC:
    def test_system_store_cleanup_rpc(self, tmp_path):
        db_file = str(tmp_path / "bridge_sessions.db")
        server = BridgeServer(store_path=db_file, fake_model=True)
        conn = MagicMock()
        conn.authenticated = True

        # Create an old session
        old_sid = server.store.create(title="Old To Cleanup")
        old_time = time.time() - (50 * 86400)
        server.store.db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (old_time, old_sid))
        server.store.db.commit()

        res = server._m_system_store_cleanup(conn, {"retention_days": 30, "max_db_mb": 100})
        assert "deleted_sessions" in res
        assert "freed_mb" in res
        assert res["deleted_sessions"] >= 1
        assert server.store.exists(old_sid) is False

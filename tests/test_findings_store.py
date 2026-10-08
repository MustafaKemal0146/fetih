"""Persistent findings store + bridge findings.* RPCs (issue #33)."""
import os
import tempfile

import pytest

from fetih_desktop_bridge.findings_store import FindingsStore, normalize_severity


@pytest.fixture
def store():
    path = os.path.join(tempfile.mkdtemp(), "findings.db")
    return FindingsStore(path)


def _f(**kw):
    base = {"title": "t", "target": "x", "severity": "medium", "evidence": "e"}
    base.update(kw)
    return base


def test_add_persists_and_assigns_id(store):
    row = store.add(_f(title="SQLi", severity="critical"), session_id="s1")
    assert row and row["id"] and row["severity"] == "Critical"
    assert store.count() == 1


def test_duplicate_is_not_stored_twice(store):
    assert store.add(_f(title="dup"), session_id="s1") is not None
    assert store.add(_f(title="dup"), session_id="s1") is None
    assert store.count() == 1


def test_same_finding_different_session_is_distinct(store):
    store.add(_f(title="dup"), session_id="s1")
    assert store.add(_f(title="dup"), session_id="s2") is not None
    assert store.count() == 2


def test_persists_across_instances(store):
    store.add(_f(title="kalıcı"), session_id="s1")
    reopened = FindingsStore(store.path)
    assert reopened.count() == 1
    assert reopened.list()[0]["title"] == "kalıcı"


def test_list_sorted_by_severity_then_filters(store):
    store.add(_f(title="low one", severity="low"), session_id="s1")
    store.add(_f(title="crit one", severity="critical"), session_id="s1")
    store.add(_f(title="med one", severity="medium"), session_id="s2")
    sev = [f["severity"] for f in store.list()]
    assert sev == ["Critical", "Medium", "Low"]
    assert len(store.list(severity="critical")) == 1
    assert len(store.list(session_id="s2")) == 1
    assert len(store.list(query="crit one")) == 1


def test_list_sort_by_time_is_newest_first(store):
    store.add(_f(title="first", severity="low"), session_id="s1")
    store.add(_f(title="second", severity="critical"), session_id="s1")
    titles = [f["title"] for f in store.list(sort="time")]
    assert titles == ["second", "first"]


def test_delete_and_clear(store):
    a = store.add(_f(title="a"), session_id="s1")
    store.add(_f(title="b"), session_id="s2")
    assert store.delete(a["id"]) is True
    assert store.delete("nope") is False
    assert store.count() == 1
    assert store.clear("s1") == 0  # a was for s1 but deleted
    store.add(_f(title="c"), session_id="s2")
    assert store.clear("s2") == 2
    assert store.count() == 0


@pytest.mark.parametrize("raw,expected", [
    ("critical", "Critical"), ("Critical", "Critical"), ("kritik", "Critical"), ("Kritik", "Critical"),
    ("high", "High"), ("yüksek", "High"), ("medium", "Medium"), ("orta", "Medium"),
    ("low", "Low"), ("düşük", "Low"), ("info", "Info"), ("", "Info"), ("weird", "Info"),
])
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


def test_list_strips_fingerprint(store):
    store.add(_f(), session_id="s1")
    assert "fingerprint" not in store.list()[0]


# ── bridge RPC wiring ──────────────────────────────────────────────────────

@pytest.fixture
def bridge(monkeypatch, tmp_path):
    monkeypatch.setenv("FETIH_HOME", str(tmp_path))
    from fetih_desktop_bridge.server import BridgeServer
    return BridgeServer(require_auth=False)


def test_rpc_list_delete_clear(bridge):
    bridge.findings.add(_f(title="SQLi", severity="critical"), session_id="s1")
    bridge.findings.add(_f(title="Leak", severity="low"), session_id="s2")

    res = bridge._m_findings_list(None, {})
    assert res["total"] == 2 and res["filtered"] == 2
    assert res["findings"][0]["severity"] == "Critical"

    only = bridge._m_findings_list(None, {"severity": "low"})
    assert only["filtered"] == 1 and only["total"] == 2

    fid = res["findings"][0]["id"]
    assert bridge._m_findings_delete(None, {"id": fid})["deleted"] is True
    assert bridge._m_findings_list(None, {})["total"] == 1
    assert bridge._m_findings_clear(None, {})["cleared"] == 1
    assert bridge._m_findings_list(None, {})["total"] == 0


def test_rpc_export_applies_filters(bridge):
    bridge.findings.add(_f(title="SQLi", severity="critical", reference="CWE-89"), session_id="s1")
    bridge.findings.add(_f(title="Leak", severity="low"), session_id="s1")
    md = bridge._m_findings_export(None, {"format": "md"})
    assert md["count"] == 2 and "SQLi" in md["content"]
    filtered = bridge._m_findings_export(None, {"format": "md", "severity": "critical"})
    assert filtered["count"] == 1 and "Leak" not in filtered["content"]


def test_rpc_delete_requires_id(bridge):
    from fetih_desktop_bridge.server import BridgeError
    with pytest.raises(BridgeError):
        bridge._m_findings_delete(None, {})

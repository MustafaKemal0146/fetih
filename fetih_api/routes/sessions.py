"""Session yönetimi rotaları."""
from __future__ import annotations
import uuid, json, time, os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from fetih_api.models.schemas import (
    SessionCreateRequest, SessionUpdateRequest, SessionInfo,
    SessionsListResponse, SessionHistoryResponse,
)

router = APIRouter()

_sessions: dict[str, dict] = {}
_sessions_dir = Path(os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))) / "sessions"

def _load_sessions_from_disk():
    """Disk'teki session'ları yükle."""
    global _sessions
    if not _sessions_dir.exists():
        return
    for d in sorted(_sessions_dir.iterdir(), key=lambda x: x.name, reverse=True):
        if d.is_dir():
            meta_file = d / "meta.json"
            if meta_file.exists():
                try:
                    with open(meta_file) as f:
                        meta = json.load(f)
                    _sessions[d.name] = {
                        "id": d.name,
                        "title": meta.get("title", ""),
                        "model": meta.get("model", ""),
                        "provider": meta.get("provider", ""),
                        "message_count": meta.get("message_count", 0),
                        "created": meta.get("created", ""),
                        "updated": meta.get("updated", ""),
                        "has_checkpoints": (d / "checkpoints").exists(),
                    }
                except Exception:
                    pass


_load_sessions_from_disk()


@router.get("/sessions", response_model=SessionsListResponse)
async def list_sessions(limit: int = Query(20), offset: int = Query(0),
                        sort: str = Query("updated"), filter: str | None = Query(None)):
    """Tüm session'ları listele."""
    sess_list = sorted(_sessions.values(), key=lambda s: s.get("updated", ""), reverse=True)
    if filter:
        fl = filter.lower()
        sess_list = [s for s in sess_list if fl in (s.get("title") or "").lower()]
    total = len(sess_list)
    page = sess_list[offset:offset+limit]
    return SessionsListResponse(
        total=total,
        sessions=[SessionInfo(**s) for s in page],
    )


@router.post("/sessions", response_model=SessionInfo)
async def create_session(req: SessionCreateRequest):
    """Yeni session oluştur."""
    sid = f"sess_{uuid.uuid4().hex[:12]}"
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    session = {
        "id": sid, "title": req.title or f"Session {sid[-6:]}",
        "model": req.model or "claude-sonnet-4-6",
        "provider": req.provider or "anthropic",
        "message_count": 0, "created": now, "updated": now,
        "has_checkpoints": False,
    }
    _sessions[sid] = session
    return SessionInfo(**session)


@router.get("/sessions/{session_id}", response_model=SessionInfo)
async def get_session(session_id: str):
    """Session detayı."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionInfo(**_sessions[session_id])


@router.get("/sessions/{session_id}/history", response_model=SessionHistoryResponse)
async def get_history(session_id: str, limit: int = Query(100)):
    """Session mesaj geçmişi."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    # Gerçek geçmişi disk'ten oku
    session_dir = _sessions_dir / session_id
    messages = []
    if session_dir.exists():
        history_file = session_dir / "messages.jsonl"
        if history_file.exists():
            try:
                with open(history_file) as f:
                    for line in f:
                        if len(messages) >= limit:
                            break
                        try:
                            messages.append(json.loads(line))
                        except Exception:
                            pass
            except Exception:
                pass
    return SessionHistoryResponse(session_id=session_id, messages=messages)


@router.put("/sessions/{session_id}", response_model=SessionInfo)
async def update_session(session_id: str, req: SessionUpdateRequest):
    """Session ayarlarını güncelle."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    if req.title is not None:
        _sessions[session_id]["title"] = req.title
    if req.model is not None:
        _sessions[session_id]["model"] = req.model
    if req.goal is not None:
        _sessions[session_id]["goal"] = req.goal
    _sessions[session_id]["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return SessionInfo(**_sessions[session_id])


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    """Session'ı sil."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    del _sessions[session_id]
    # Disk'ten de sil
    session_dir = _sessions_dir / session_id
    if session_dir.exists():
        import shutil
        shutil.rmtree(session_dir, ignore_errors=True)
    return {"status": "deleted", "session_id": session_id}


@router.post("/sessions/{session_id}/export")
async def export_session(session_id: str, format: str = Query("json")):
    """Session'ı dışa aktar."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    session = _sessions[session_id]
    if format == "json":
        return session
    elif format == "markdown":
        lines = [f"# {session.get('title', 'Session')}", "",
                 f"**Model:** {session.get('model', '')}",
                 f"**Created:** {session.get('created', '')}", ""]
        return {"format": "markdown", "content": "\n".join(lines)}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

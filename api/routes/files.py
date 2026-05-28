"""Dosya yönetimi rotaları."""
from __future__ import annotations
import uuid, os, shutil, time
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from fastapi.responses import FileResponse
from api.models.schemas import FileInfo

router = APIRouter()
_upload_dir = Path("/tmp/fetih_uploads")
_upload_dir.mkdir(parents=True, exist_ok=True)
_files: dict[str, dict] = {}


@router.post("/files/upload", response_model=FileInfo)
async def upload_file(file: UploadFile = File(...)):
    """Dosya yükle."""
    file_id = f"file_{uuid.uuid4().hex[:8]}"
    dest = _upload_dir / f"{file_id}_{file.filename}"
    content = await file.read()

    with open(dest, "wb") as f:
        f.write(content)

    info = {
        "file_id": file_id, "name": file.filename or "unknown",
        "size": len(content), "type": file.content_type or "application/octet-stream",
        "path": str(dest), "uploaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _files[file_id] = info
    return FileInfo(**info)


@router.get("/files", response_model=list[FileInfo])
async def list_files():
    """Yüklenen dosyaları listele."""
    return [FileInfo(**f) for f in _files.values()]


@router.get("/files/{file_id}", response_model=FileInfo)
async def get_file(file_id: str):
    """Dosya bilgisi."""
    if file_id not in _files:
        raise HTTPException(status_code=404, detail="File not found")
    return FileInfo(**_files[file_id])


@router.get("/files/{file_id}/download")
async def download_file(file_id: str):
    """Dosyayı indir."""
    if file_id not in _files:
        raise HTTPException(status_code=404, detail="File not found")
    path = _files[file_id]["path"]
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    return FileResponse(path, filename=_files[file_id]["name"])


@router.delete("/files/{file_id}")
async def delete_file(file_id: str):
    """Dosyayı sil."""
    if file_id not in _files:
        raise HTTPException(status_code=404, detail="File not found")
    path = _files[file_id]["path"]
    if os.path.exists(path):
        os.remove(path)
    del _files[file_id]
    return {"status": "deleted", "file_id": file_id}

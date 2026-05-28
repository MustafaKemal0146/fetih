"""Cron & otomasyon rotaları."""
from __future__ import annotations
import uuid
from fastapi import APIRouter, HTTPException
from fetih_api.models.schemas import CronJobInfo, CronCreateRequest

router = APIRouter()
_cron_jobs: dict[str, dict] = {}


@router.get("/cron", response_model=list[CronJobInfo])
async def list_cron():
    """Zamanlanmış görevleri listele."""
    return [CronJobInfo(id=i, **{k: v for k, v in j.items() if k != "id"})
            for i, j in _cron_jobs.items()]


@router.post("/cron", response_model=CronJobInfo)
async def create_cron(req: CronCreateRequest):
    """Yeni cron görevi oluştur."""
    job_id = f"cron_{uuid.uuid4().hex[:8]}"
    job = {
        "id": job_id, "schedule": req.schedule, "prompt": req.prompt,
        "model": req.model or "claude-sonnet-4-6",
        "session_id": req.session_id, "enabled": True,
        "last_run": None, "next_run": "pending",
    }
    _cron_jobs[job_id] = job
    return CronJobInfo(**job)


@router.put("/cron/{job_id}", response_model=CronJobInfo)
async def update_cron(job_id: str, req: CronCreateRequest):
    """Cron görevini güncelle."""
    if job_id not in _cron_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    _cron_jobs[job_id].update(req.model_dump(exclude_unset=True))
    return CronJobInfo(**_cron_jobs[job_id])


@router.delete("/cron/{job_id}")
async def delete_cron(job_id: str):
    """Cron görevini sil."""
    if job_id not in _cron_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    del _cron_jobs[job_id]
    return {"status": "deleted", "job_id": job_id}


@router.post("/cron/{job_id}/trigger")
async def trigger_cron(job_id: str):
    """Cron görevini hemen çalıştır."""
    if job_id not in _cron_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    _cron_jobs[job_id]["last_run"] = "triggered"
    return {"status": "triggered", "job_id": job_id, "prompt": _cron_jobs[job_id]["prompt"]}

"""Sistem & sağlık rotaları."""
from __future__ import annotations
import os, sys, time, platform
from fastapi import APIRouter, Query
from api.models.schemas import HealthResponse, StatusResponse

router = APIRouter()
_start_time = time.time()


def _task_counts() -> tuple[int, int]:
    """(çalışan, kuyrukta) arkaplan görev sayıları."""
    try:
        from api.routes.deps import _active_tasks
        running = sum(1 for t in _active_tasks.values() if t.get("status") == "running")
        queued = sum(1 for t in _active_tasks.values() if t.get("status") == "queued")
        return running, queued
    except Exception:
        return 0, 0


@router.get("/health", response_model=HealthResponse)
async def health():
    """Health check."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    running, _queued = _task_counts()
    return HealthResponse(
        status="ok", uptime=round(time.time() - _start_time, 1),
        version="5.1.0", python=py_ver,
        agent_status="busy" if running else "idle", active_sessions=running,
    )


@router.get("/status", response_model=StatusResponse)
async def status():
    """Detaylı sistem durumu."""
    try:
        import psutil
        cpu = psutil.cpu_percent()
        mem = psutil.Process().memory_info().rss / 1024 / 1024
        open_files = len(psutil.Process().open_files())
        threads = psutil.Process().num_threads()
    except ImportError:
        cpu, mem, open_files, threads = 0, 0, 0, 0

    running, queued = _task_counts()
    return StatusResponse(
        cpu_percent=cpu, memory_mb=round(mem, 1),
        open_files=open_files, threads=threads,
        active_tasks=running, queued_tasks=queued,
    )


@router.get("/version")
async def version():
    """Sürüm bilgisi."""
    return {
        "version": "5.1.0", "api_version": "1.0.0",
        "python": platform.python_version(), "platform": platform.platform(),
        "port": os.environ.get("FETIH_API_PORT", "1453"),
    }


@router.get("/usage")
async def usage(period: str = Query("7d")):
    """Token kullanım istatistikleri."""
    return {"period": period, "total_tokens": 0, "total_cost": 0, "by_model": {}, "by_date": []}

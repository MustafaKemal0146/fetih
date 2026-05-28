"""Sistem & sağlık rotaları."""
from __future__ import annotations
import os, sys, time, platform
from fastapi import APIRouter, Query
from fetih_api.models.schemas import HealthResponse, StatusResponse

router = APIRouter()
_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health():
    """Health check."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    return HealthResponse(
        status="ok", uptime=round(time.time() - _start_time, 1),
        version="5.1.0", python=py_ver,
        agent_status="idle", active_sessions=0,
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

    return StatusResponse(
        cpu_percent=cpu, memory_mb=round(mem, 1),
        open_files=open_files, threads=threads,
        active_tasks=0, queued_tasks=0,
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

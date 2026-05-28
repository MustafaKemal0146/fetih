"""Gateway yönetimi rotaları."""
from __future__ import annotations
import os, time, platform as _platform
from fastapi import APIRouter
from fetih_api.models.schemas import GatewayStatusResponse, GatewayActionRequest, PlatformInfo

router = APIRouter()
_gateway_start_time = time.time()
_gateway_running = False


@router.get("/gateway/status", response_model=GatewayStatusResponse)
async def gateway_status():
    """Gateway durumu."""
    return GatewayStatusResponse(
        running=_gateway_running,
        pids=[os.getpid()] if _gateway_running else [],
        service="systemd" if _platform.system() == "Linux" else "manual",
        platform=_platform.system().lower(),
        uptime_seconds=int(time.time() - _gateway_start_time) if _gateway_running else 0,
        profiles=["default"],
    )


@router.post("/gateway/start")
async def gateway_start(req: GatewayActionRequest | None = None):
    """Gateway başlat."""
    global _gateway_running, _gateway_start_time
    _gateway_running = True
    _gateway_start_time = time.time()
    return {"status": "started", "message": "Gateway running"}


@router.post("/gateway/stop")
async def gateway_stop(req: GatewayActionRequest | None = None):
    """Gateway durdur."""
    global _gateway_running
    _gateway_running = False
    return {"status": "stopped", "message": "Gateway stopped"}


@router.post("/gateway/restart")
async def gateway_restart(req: GatewayActionRequest | None = None):
    """Gateway yeniden başlat."""
    global _gateway_start_time
    _gateway_start_time = time.time()
    return {"status": "restarted", "message": "Gateway restarted"}


@router.get("/gateway/platforms", response_model=list[PlatformInfo])
async def gateway_platforms():
    """Platform durumlarını listele."""
    return [PlatformInfo(platform="api", status="connected", chats=1)]


@router.post("/gateway/platforms/{name}/pause")
async def platform_pause(name: str):
    return {"status": "paused", "platform": name}


@router.post("/gateway/platforms/{name}/resume")
async def platform_resume(name: str):
    return {"status": "resumed", "platform": name}

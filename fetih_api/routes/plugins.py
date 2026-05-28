"""Plugin yönetimi rotaları."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from fetih_api.models.schemas import PluginInfo, PluginInstallRequest

router = APIRouter()
_plugins: dict[str, dict] = {}


@router.get("/plugins", response_model=list[PluginInfo])
async def list_plugins():
    """Kurulu plugin'leri listele."""
    return [PluginInfo(name=n, version=i.get("version", "0.1.0"),
                       description=i.get("description", ""), status="active")
            for n, i in _plugins.items()] or [
        PluginInfo(name="api-server", version="1.0.0", description="FETIH REST API", status="active")
    ]


@router.post("/plugins/install", response_model=PluginInfo)
async def install_plugin(req: PluginInstallRequest):
    """Plugin yükle."""
    import subprocess, re
    name = req.url.rstrip("/").split("/")[-1].replace(".git", "")
    try:
        result = subprocess.run(["git", "clone", req.url, f"/tmp/fetih_plugin_{name}"],
                                capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Clone failed: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Clone timed out")

    _plugins[name] = {"version": "0.1.0", "description": f"Installed from {req.url}"}
    return PluginInfo(name=name, version="0.1.0", description=f"Installed from {req.url}", status="active")


@router.delete("/plugins/{name}")
async def delete_plugin(name: str):
    """Plugin kaldır."""
    if name not in _plugins:
        raise HTTPException(status_code=404, detail="Plugin not found")
    del _plugins[name]
    return {"status": "deleted", "plugin": name}

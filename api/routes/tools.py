"""Tool yönetimi rotaları."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from api.models.schemas import ToolInfo, ToolsListResponse, ToolsModifyRequest

router = APIRouter()

_known_tools = [
    {"name": "bash", "toolset": "terminal", "enabled": True, "description": "Shell komutu çalıştır"},
    {"name": "read", "toolset": "terminal", "enabled": True, "description": "Dosya oku"},
    {"name": "write", "toolset": "terminal", "enabled": True, "description": "Dosya yaz"},
    {"name": "edit", "toolset": "terminal", "enabled": True, "description": "Dosya düzenle"},
    {"name": "glob", "toolset": "terminal", "enabled": True, "description": "Dosya ara"},
    {"name": "grep", "toolset": "terminal", "enabled": True, "description": "İçerik ara"},
    {"name": "web_search", "toolset": "web", "enabled": True, "description": "Web araması"},
    {"name": "web_fetch", "toolset": "web", "enabled": True, "description": "Sayfa getir"},
    {"name": "browser", "toolset": "browser", "enabled": False, "description": "Tarayıcı kontrolü"},
    {"name": "memory", "toolset": "memory", "enabled": True, "description": "Kayıt/hatırlama"},
    {"name": "skill", "toolset": "skills", "enabled": True, "description": "Skill yükle"},
]
_disabled: set[str] = set()


@router.get("/tools", response_model=ToolsListResponse)
async def list_tools():
    """Aktif tool'ları listele."""
    toolsets = list(set(t["toolset"] for t in _known_tools))
    tools = []
    for t in _known_tools:
        enabled = t["name"] not in _disabled and t["enabled"]
        tools.append(ToolInfo(name=t["name"], toolset=t["toolset"], enabled=enabled, description=t["description"]))
    return ToolsListResponse(toolsets=toolsets, tools=tools)


@router.post("/tools/enable")
async def enable_tools(req: ToolsModifyRequest):
    """Tool/toolset aktifleştir."""
    if req.tools:
        for name in req.tools:
            _disabled.discard(name)
    return {"status": "ok", "enabled": req.tools or req.toolsets}


@router.post("/tools/disable")
async def disable_tools(req: ToolsModifyRequest):
    """Tool/toolset deaktif et."""
    if req.tools:
        for name in req.tools:
            _disabled.add(name)
    if req.toolsets:
        for ts in req.toolsets:
            for t in _known_tools:
                if t["toolset"] == ts:
                    _disabled.add(t["name"])
    return {"status": "ok", "disabled": list(_disabled)}


@router.get("/tools/available")
async def available_tools():
    """Kurulu ama aktif olmayan tool'lar."""
    return {"available": [t for t in _known_tools if t["name"] not in _disabled and not t["enabled"]]}


@router.get("/tools/{name}/schema")
async def tool_schema(name: str):
    """Tool JSON şeması."""
    for t in _known_tools:
        if t["name"] == name:
            return {"name": name, "description": t["description"], "toolset": t["toolset"]}
    raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")

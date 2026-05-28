"""Profil yönetimi rotaları."""
from __future__ import annotations
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fetih_api.models.schemas import ProfileInfo, ProfilesListResponse, ProfileCreateRequest

router = APIRouter()

# Modül yüklenirken orijinal home'u sakla (activate sonrası değişmesin diye)
_ORIGINAL_HOME = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))


def _get_profiles_dir() -> Path:
    return Path(_ORIGINAL_HOME) / "profiles"


@router.get("/profiles", response_model=ProfilesListResponse)
async def list_profiles():
    """Profil listesi."""
    profiles_dir = _get_profiles_dir()
    profiles = []
    active = "default"

    if profiles_dir.exists():
        for d in profiles_dir.iterdir():
            if d.is_dir():
                skill_count = len(list(d.rglob("SKILL.md"))) if (d / "skills").exists() else 0
                profiles.append(ProfileInfo(name=d.name, home=str(d),
                                           model="claude-sonnet-4-6",
                                           skills=skill_count))
    if not profiles:
        profiles.append(ProfileInfo(name="default", home=str(profiles_dir / "default"),
                                    model="claude-sonnet-4-6", skills=916))
    return ProfilesListResponse(active=active, profiles=profiles)


@router.post("/profiles", response_model=ProfileInfo)
async def create_profile(req: ProfileCreateRequest):
    """Yeni profil oluştur."""
    profiles_dir = _get_profiles_dir()
    profile_dir = profiles_dir / req.name
    if profile_dir.exists():
        raise HTTPException(status_code=409, detail=f"Profile '{req.name}' already exists")
    profile_dir.mkdir(parents=True, exist_ok=True)
    if req.copy_from:
        src = profiles_dir / req.copy_from
        if src.exists():
            import shutil
            shutil.copytree(src, profile_dir, dirs_exist_ok=True)
    return ProfileInfo(name=req.name, home=str(profile_dir), skills=0)


@router.post("/profiles/{name}/activate")
async def activate_profile(name: str):
    """Profil değiştir."""
    profile_dir = _get_profiles_dir() / name
    if not profile_dir.exists():
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")
    os.environ["FETIH_HOME"] = str(profile_dir)
    return {"status": "activated", "profile": name, "home": str(profile_dir)}


@router.delete("/profiles/{name}")
async def delete_profile(name: str):
    """Profil sil."""
    if name == "default":
        raise HTTPException(status_code=400, detail="Cannot delete default profile")
    profile_dir = _get_profiles_dir() / name
    if not profile_dir.exists():
        raise HTTPException(status_code=404, detail=f"Profile '{name}' not found")
    import shutil
    shutil.rmtree(profile_dir, ignore_errors=True)
    return {"status": "deleted", "profile": name}

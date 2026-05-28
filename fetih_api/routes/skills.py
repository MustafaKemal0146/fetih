"""Skill yönetimi rotaları."""
from __future__ import annotations
import os, sys, yaml
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from fetih_api.models.schemas import (
    SkillInfo, SkillsListResponse, SkillSearchRequest,
)

router = APIRouter()

_skills_cache: list[SkillInfo] | None = None
_skills_dir = Path(__file__).parent.parent.parent / "skills"


def _load_skills() -> list[SkillInfo]:
    """Tüm skill'leri tara ve cache'le."""
    global _skills_cache
    if _skills_cache is not None:
        return _skills_cache

    skills = []
    for sk_md in _skills_dir.rglob("SKILL.md"):
        try:
            with open(sk_md) as f:
                content = f.read()
            fm = {}
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    fm = yaml.safe_load(parts[1]) or {}

            rel_path = str(sk_md.relative_to(_skills_dir.parent))
            skills.append(SkillInfo(
                name=fm.get("name", sk_md.parent.name),
                category=fm.get("category", rel_path.split("/")[1] if len(rel_path.split("/")) > 1 else ""),
                description=fm.get("description", "")[:200],
                tags=fm.get("tags", []) or [],
                triggers=fm.get("triggers", []) or [],
                mitre_attack=fm.get("mitre_attack", []) or [],
                nist_csf=fm.get("nist_csf", []) or [],
                source=fm.get("source"),
                file_path=rel_path,
            ))
        except Exception:
            pass

    _skills_cache = skills
    return skills


@router.get("/skills", response_model=SkillsListResponse)
async def list_skills(
    category: str | None = Query(None), search: str | None = Query(None),
    limit: int = Query(50), offset: int = Query(0),
):
    """Tüm skill'leri listele."""
    all_skills = _load_skills()
    filtered = all_skills

    if category:
        filtered = [s for s in filtered if s.category == category]
    if search:
        q = search.lower()
        filtered = [s for s in filtered if
                    q in s.name.lower() or q in s.description.lower() or
                    any(q in t.lower() for t in s.triggers) or
                    any(q in t.lower() for t in s.tags)]

    total = len(filtered)
    page = filtered[offset:offset+limit]
    return SkillsListResponse(total=total, skills=page)


@router.get("/skills/categories")
async def list_categories():
    """Kategori listesi ve sayıları."""
    all_skills = _load_skills()
    cats: dict[str, int] = {}
    for s in all_skills:
        cats[s.category] = cats.get(s.category, 0) + 1
    return {"categories": dict(sorted(cats.items(), key=lambda x: -x[1]))}


@router.get("/skills/{name}", response_model=SkillInfo)
async def get_skill(name: str):
    """Skill detayı."""
    all_skills = _load_skills()
    for s in all_skills:
        if s.name == name:
            return s
    raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")


@router.get("/skills/{name}/raw")
async def get_skill_raw(name: str):
    """Ham SKILL.md içeriği."""
    all_skills = _load_skills()
    for s in all_skills:
        if s.name == name:
            full_path = _skills_dir.parent / s.file_path
            if full_path.exists():
                return {"name": name, "content": full_path.read_text()}
    raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")


@router.post("/skills/search")
async def search_skills(req: SkillSearchRequest):
    """Gelişmiş skill araması."""
    all_skills = _load_skills()
    results = all_skills

    if req.query:
        q = req.query.lower()
        results = [s for s in results if
                   q in s.name.lower() or q in s.description.lower() or
                   any(q in t.lower() for t in s.triggers + s.tags)]
    if req.category:
        results = [s for s in results if s.category == req.category]
    if req.mitre_tech:
        results = [s for s in results if req.mitre_tech in s.mitre_attack]
    if req.nist_csf:
        results = [s for s in results if any(req.nist_csf in n for n in s.nist_csf)]
    if req.tool:
        q = req.tool.lower()
        results = [s for s in results if any(q in t.lower() for t in s.tags)]

    return {"total": len(results), "skills": results[:req.limit]}


@router.post("/skills/reload")
async def reload_skills():
    """Skill cache'ini yenile."""
    global _skills_cache
    _skills_cache = None
    all_skills = _load_skills()
    return {"status": "reloaded", "total": len(all_skills)}

"""Model yönetimi rotaları."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from api.models.schemas import (
    ModelInfo, ModelsListResponse, ModelSwitchRequest,
    ModelParamsRequest, ProviderCreateRequest,
)
from api.routes.deps import get_agent_config

router = APIRouter()

_known_models = [
    ModelInfo(id="claude-sonnet-4-6", provider="anthropic", display_name="Claude Sonnet 4.6",
              context_length=200000, max_output_tokens=32000, supports_reasoning=True,
              supports_vision=True, recommended=True, pricing={"input": 3.0, "output": 15.0, "cache_read": 0.30}),
    ModelInfo(id="claude-opus-4-5", provider="anthropic", display_name="Claude Opus 4.5",
              context_length=200000, max_output_tokens=32000, supports_reasoning=True,
              supports_vision=True, pricing={"input": 15.0, "output": 75.0, "cache_read": 1.50}),
    ModelInfo(id="claude-haiku-4-5", provider="anthropic", display_name="Claude Haiku 4.5",
              context_length=200000, max_output_tokens=32000, supports_reasoning=False,
              supports_vision=True, pricing={"input": 1.0, "output": 5.0, "cache_read": 0.10}),
    ModelInfo(id="gpt-5", provider="openai", display_name="GPT-5",
              context_length=128000, max_output_tokens=16384, supports_reasoning=True,
              supports_vision=True, pricing={"input": 2.5, "output": 10.0}),
    ModelInfo(id="gpt-5-mini", provider="openai", display_name="GPT-5 Mini",
              context_length=128000, max_output_tokens=16384, supports_reasoning=False,
              supports_vision=True, pricing={"input": 0.50, "output": 2.0}),
    ModelInfo(id="deepseek-v4-pro", provider="deepseek", display_name="DeepSeek V4 Pro",
              context_length=128000, max_output_tokens=32768, supports_reasoning=True,
              supports_vision=False, pricing={"input": 0.55, "output": 2.19}),
    ModelInfo(id="deepseek-v4-flash", provider="deepseek", display_name="DeepSeek V4 Flash",
              context_length=128000, max_output_tokens=32768, supports_reasoning=False,
              supports_vision=False, pricing={"input": 0.14, "output": 0.55}),
    ModelInfo(id="gemini-3.0-pro", provider="google", display_name="Gemini 3.0 Pro",
              context_length=1000000, max_output_tokens=65536, supports_reasoning=True,
              supports_vision=True, free=True, recommended=True, pricing={}),
    ModelInfo(id="gemini-3.0-flash", provider="google", display_name="Gemini 3.0 Flash",
              context_length=1000000, max_output_tokens=65536, supports_reasoning=False,
              supports_vision=True, free=True, pricing={}),
    ModelInfo(id="grok-4.20", provider="xai", display_name="Grok 4.20",
              context_length=128000, max_output_tokens=16384, supports_reasoning=True,
              supports_vision=True, pricing={"input": 2.0, "output": 8.0}),
]

_providers = ["anthropic", "openai", "deepseek", "google", "xai", "nous", "openrouter"]
_custom_providers: dict[str, dict] = {}

_model_params: dict = {"temperature": 0.7, "max_tokens": None, "top_p": 1.0,
                        "reasoning": {"enabled": False, "effort": "medium"},
                        "thinking_budget": None, "service_tier": None}


@router.get("/models", response_model=ModelsListResponse)
async def list_models(provider: str | None = Query(None), filter: str | None = Query(None)):
    """Tüm modelleri listele (provider bazlı filtreleme ile)."""
    cfg = get_agent_config()
    models = _known_models
    if provider:
        models = [m for m in models if m.provider == provider]
    if filter:
        fl = filter.lower()
        models = [m for m in models if fl in m.id.lower() or fl in m.display_name.lower()]
    return ModelsListResponse(
        providers=_providers,
        current_model=cfg.get("model", ""),
        current_provider=cfg.get("provider", ""),
        models=models,
    )


@router.post("/models/switch")
async def switch_model(req: ModelSwitchRequest):
    """Model değiştir."""
    import os
    if req.provider:
        os.environ["FETIH_PROVIDER"] = req.provider
    os.environ["FETIH_MODEL"] = req.model
    return {"status": "ok", "model": req.model, "provider": req.provider, "session_id": req.session_id}


@router.get("/models/params")
async def get_model_params(session_id: str | None = Query(None)):
    """Model parametrelerini getir."""
    return {**_model_params, "session_id": session_id}


@router.post("/models/params")
async def set_model_params(req: ModelParamsRequest):
    """Model parametrelerini güncelle."""
    updates = {}
    if req.temperature is not None:
        _model_params["temperature"] = req.temperature
        updates["temperature"] = req.temperature
    if req.max_tokens is not None:
        _model_params["max_tokens"] = req.max_tokens
        updates["max_tokens"] = req.max_tokens
    if req.top_p is not None:
        _model_params["top_p"] = req.top_p
        updates["top_p"] = req.top_p
    if req.reasoning is not None:
        _model_params["reasoning"] = req.reasoning.model_dump()
        updates["reasoning"] = req.reasoning.model_dump()
    if req.thinking_budget is not None:
        _model_params["thinking_budget"] = req.thinking_budget
        updates["thinking_budget"] = req.thinking_budget
    if req.service_tier is not None:
        _model_params["service_tier"] = req.service_tier
        updates["service_tier"] = req.service_tier
    return {"status": "ok", "updated": updates, "session_id": req.session_id}


@router.get("/models/providers")
async def list_providers():
    """Provider listesi (auth durumuyla)."""
    import os
    result = []
    auth_envs = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "google": "GEMINI_API_KEY",
        "xai": "XAI_API_KEY",
    }
    for p in _providers:
        has_auth = bool(os.environ.get(auth_envs.get(p, "")))
        result.append({"slug": p, "display_name": p.title(), "has_auth": has_auth,
                       "is_custom": p in _custom_providers})
    for slug, info in _custom_providers.items():
        result.append({"slug": slug, "display_name": info.get("display_name", slug),
                       "has_auth": True, "is_custom": True})
    return {"providers": result}


@router.post("/models/providers")
async def create_provider(req: ProviderCreateRequest):
    """Yeni custom provider ekle."""
    _custom_providers[req.slug] = req.model_dump()
    if req.slug not in _providers:
        _providers.append(req.slug)
    return {"status": "ok", "slug": req.slug}


@router.delete("/models/providers/{slug}")
async def delete_provider(slug: str):
    """Custom provider'ı sil."""
    if slug not in _custom_providers:
        raise HTTPException(status_code=404, detail=f"Custom provider '{slug}' not found")
    del _custom_providers[slug]
    if slug in _providers:
        _providers.remove(slug)
    return {"status": "deleted", "slug": slug}

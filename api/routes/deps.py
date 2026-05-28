"""Ortak bağımlılıklar ve yardımcılar."""
from __future__ import annotations
import os, sys, uuid, time, logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("fetih_api.deps")

# Agent instance cache
_agent_cache: dict[str, any] = {}
_active_tasks: dict[str, dict] = {}
_agent_params: dict = {}

def _get_project_root() -> Path:
    return Path(__file__).parent.parent.parent.resolve()

def _ensure_path():
    root = str(_get_project_root())
    if root not in sys.path:
        sys.path.insert(0, root)

_ensure_path()

def get_agent_config() -> dict:
    """~/.fetih/config.yaml'dan agent konfigürasyonunu oku."""
    import yaml
    home = os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih"))
    config_path = Path(home) / "config.yaml"
    cfg = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            pass

    model_val = cfg.get("model", "")
    if isinstance(model_val, dict):
        model_val = model_val.get("default", model_val.get("name", ""))
    provider_val = cfg.get("provider", "")
    if isinstance(provider_val, dict):
        provider_val = provider_val.get("default", provider_val.get("name", ""))

    result = {
        "model": str(model_val) if model_val else os.environ.get("FETIH_MODEL", "claude-sonnet-4-6"),
        "provider": str(provider_val) if provider_val else os.environ.get("FETIH_PROVIDER", "anthropic"),
        "base_url": os.environ.get("ANTHROPIC_BASE_URL", ""),
        "api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
        "max_iterations": 90,
    }
    return result

def get_or_create_agent(
    model: str | None = None,
    provider: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    max_iterations: int = 90,
    session_id: str | None = None,
    **kwargs,
):
    """Agent instance'ı oluştur veya cache'den al."""
    from run_agent import AIAgent
    global _agent_cache

    cfg = get_agent_config()
    use_model = model or cfg["model"]
    use_provider = provider or cfg["provider"]
    use_api_key = api_key or cfg["api_key"]
    use_base_url = base_url or cfg["base_url"]

    cache_key = f"{use_model}:{use_provider}:{session_id or ''}"
    if cache_key in _agent_cache:
        return _agent_cache[cache_key]

    try:
        agent = AIAgent(
            model=use_model,
            provider=use_provider,
            api_key=use_api_key or None,
            base_url=use_base_url or None,
            max_iterations=max_iterations,
            session_id=session_id or str(uuid.uuid4())[:8],
            quiet_mode=True,
            platform="api",
        )
    except Exception as e:
        logger.warning("Agent init with full config failed: %s, falling back to minimal", e)
        agent = AIAgent(
            model=use_model,
            max_iterations=max_iterations,
            quiet_mode=True,
            platform="api",
        )

    if len(_agent_cache) > 50:
        _agent_cache.pop(next(iter(_agent_cache)))
    _agent_cache[cache_key] = agent
    return agent


def submit_background_task(task_id: str, fn, *args, **kwargs):
    """Arkaplan görevi başlat."""
    import threading
    _active_tasks[task_id] = {"status": "queued", "result": None, "progress": {"iteration": 0}}

    def _run():
        try:
            _active_tasks[task_id]["status"] = "running"
            result = fn(*args, **kwargs)
            _active_tasks[task_id]["status"] = "done"
            _active_tasks[task_id]["result"] = result
        except Exception as e:
            _active_tasks[task_id]["status"] = "error"
            _active_tasks[task_id]["error"] = str(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return task_id


def get_task_status(task_id: str) -> dict | None:
    return _active_tasks.get(task_id)


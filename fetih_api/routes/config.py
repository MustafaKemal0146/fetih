"""Konfigürasyon rotaları."""
from __future__ import annotations
import os, yaml
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fetih_api.models.schemas import ConfigValueResponse, ConfigSetRequest, ConfigPatchRequest

router = APIRouter()

_home = Path(os.environ.get("FETIH_HOME", os.path.expanduser("~/.fetih")))
_config_path = _home / "config.yaml"
_env_path = _home / ".env"


def _read_config() -> dict:
    if _config_path.exists():
        try:
            with open(_config_path) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {}


def _write_config(cfg: dict):
    _home.mkdir(parents=True, exist_ok=True)
    with open(_config_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)


def _read_env() -> dict:
    env = {}
    if _env_path.exists():
        with open(_env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _write_env(env: dict):
    _home.mkdir(parents=True, exist_ok=True)
    existing = _read_env()
    existing.update(env)
    with open(_env_path, "w") as f:
        for k, v in existing.items():
            f.write(f'{k}="{v}"\n')


def _nested_get(cfg: dict, dotted_key: str):
    parts = dotted_key.split(".")
    current = cfg
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _nested_set(cfg: dict, dotted_key: str, value):
    parts = dotted_key.split(".")
    current = cfg
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


@router.get("/config")
async def get_config():
    """Tüm konfigürasyonu getir."""
    cfg = _read_config()
    env = _read_env()
    return {"config": cfg, "env_keys": list(env.keys()),
            "home": str(_home), "config_path": str(_config_path)}


@router.get("/config/{key:path}", response_model=ConfigValueResponse)
async def get_config_value(key: str):
    """Tek bir konfigürasyon değerini getir."""
    cfg = _read_config()
    value = _nested_get(cfg, key)
    if value is None:
        env = _read_env()
        if key in env:
            value = env[key]
    return ConfigValueResponse(key=key, value=value, type=type(value).__name__)


@router.put("/config/{key:path}")
async def set_config_value(key: str, req: ConfigSetRequest):
    """Konfigürasyon değerini güncelle."""
    cfg = _read_config()
    _nested_set(cfg, key, req.value)
    _write_config(cfg)
    return {"status": "ok", "key": key, "value": req.value}


@router.patch("/config")
async def patch_config(req: ConfigPatchRequest):
    """Çoklu konfigürasyon güncellemesi."""
    cfg = _read_config()
    for key, value in req.updates.items():
        _nested_set(cfg, key, value)
    _write_config(cfg)
    return {"status": "ok", "updated": list(req.updates.keys())}


@router.get("/config/env")
async def get_env():
    """.env değerlerini listele."""
    return {"env": _read_env(), "path": str(_env_path)}


@router.put("/config/env/{key}")
async def set_env_value(key: str, req: ConfigSetRequest):
    """.env değerini güncelle."""
    _write_env({key: str(req.value)})
    os.environ[key] = str(req.value)
    return {"status": "ok", "key": key, "value": str(req.value)}


@router.post("/config/reload")
async def reload_config():
    """Konfigürasyonu yeniden yükle."""
    cfg = _read_config()
    return {"status": "reloaded", "keys": list(cfg.keys())}

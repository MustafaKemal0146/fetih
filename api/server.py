#!/usr/bin/env python3
"""
FETIH REST API Sunucusu — Tam yönetim HTTP API.

Kullanım:
    python -m api.server
    python -m api.server --port 1453 --host 0.0.0.0

Env:
    FETIH_API_PORT  — Port (varsayılan: 1453)
    FETIH_API_HOST  — Host (varsayılan: 127.0.0.1)
    FETIH_API_KEY   — API key (tanımlı değilse auth'suz)
"""
from __future__ import annotations
import os
import sys
import time
import logging
from contextlib import asynccontextmanager
from pathlib import Path

# Proje root'unu path'e ekle
_project_root = Path(__file__).parent.parent.resolve()
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from api.routes import (
    chat, models, sessions, skills, tools, config,
    gateway, profiles, files, plugins, cron_routes,
    system_routes,
)

logger = logging.getLogger("fetih_api")
START_TIME = time.time()
_active_sessions: dict[str, int] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama yaşam döngüsü."""
    logger.info("FETIH API başlatılıyor... (port: %s)", os.environ.get("FETIH_API_PORT", "1453"))
    yield
    logger.info("FETIH API kapatılıyor...")


app = FastAPI(
    title="FETIH API",
    description="FETIH AI Agent REST API — Tüm becerileri HTTP üzerinden yönetin",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rotaları kaydet ──────────────────────────────────────────────────────────

app.include_router(chat.router, prefix="/api/v1", tags=["Chat"])
app.include_router(models.router, prefix="/api/v1", tags=["Models"])
app.include_router(sessions.router, prefix="/api/v1", tags=["Sessions"])
app.include_router(skills.router, prefix="/api/v1", tags=["Skills"])
app.include_router(tools.router, prefix="/api/v1", tags=["Tools"])
app.include_router(config.router, prefix="/api/v1", tags=["Config"])
app.include_router(gateway.router, prefix="/api/v1", tags=["Gateway"])
app.include_router(profiles.router, prefix="/api/v1", tags=["Profiles"])
app.include_router(files.router, prefix="/api/v1", tags=["Files"])
app.include_router(plugins.router, prefix="/api/v1", tags=["Plugins"])
app.include_router(cron_routes.router, prefix="/api/v1", tags=["Cron"])
app.include_router(system_routes.router, prefix="/api/v1", tags=["System"])



@app.get("/api/v1/health", tags=["System"])
async def health_root():
    return await system_routes.health()


def main():
    """CLI giriş noktası."""
    import argparse
    parser = argparse.ArgumentParser(description="FETIH REST API Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("FETIH_API_PORT", "1453")))
    parser.add_argument("--host", default=os.environ.get("FETIH_API_HOST", "127.0.0.1"))
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    print(f"""
    ╔══════════════════════════════════════════════╗
    ║         ⚔  FETIH API Server  ⚔              ║
    ╠══════════════════════════════════════════════╣
    ║  Port     : {args.port:<6}                          ║
    ║  Host     : {args.host:<20}      ║
    ║  Docs     : http://{args.host}:{args.port}/api/docs     ║
    ║  Health   : http://{args.host}:{args.port}/api/v1/health ║
    ╚══════════════════════════════════════════════╝
    """)

    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()

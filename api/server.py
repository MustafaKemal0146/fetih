#!/usr/bin/env python3
"""
FETIH REST API Sunucusu — Tam yönetim HTTP API.

Kullanım:
    python3 api/server.py
    python3 api/server.py --port 1453 --host 0.0.0.0
    python3 -m api.server --port 1453

Env:
    FETIH_API_PORT  — Port (varsayılan: 1453)
    FETIH_API_HOST  — Host (varsayılan: 127.0.0.1)
    FETIH_API_KEY   — API key (tanımlı değilse auth'suz)
"""
from __future__ import annotations
import os, sys, time, logging, signal, argparse
from contextlib import asynccontextmanager
from pathlib import Path

# Proje root'unu path'e ekle
_project_root = Path(__file__).parent.parent.resolve()
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

logger = logging.getLogger("fetih.api")
START_TIME = time.time()

# ── FastAPI App ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("FETIH API v1 başlatıldı")
    yield
    logger.info("FETIH API kapatılıyor...")

app = FastAPI(
    title="FETIH API",
    description="FETIH AI Agent REST API — 69 endpoint ile tam yönetim. Chat, model, session, skill, tool, config, gateway, profil, dosya, plugin, cron, sistem.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    contact={"name": "FETIH", "url": "https://github.com/MustafaKemal0146/fetih"},
    license_info={"name": "MIT"},
)

# CORS — tüm origin'lere açık
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "code": "INTERNAL_ERROR", "path": str(request.url.path)},
    )

# ── Rotalar ─────────────────────────────────────────────────────────────────

from api.routes import (
    chat, models, sessions, skills, tools, config,
    gateway, profiles, files, plugins, cron_routes,
    system_routes,
)

app.include_router(chat.router,          prefix="/api/v1", tags=["💬 Chat"])
app.include_router(models.router,        prefix="/api/v1", tags=["🤖 Models"])
app.include_router(sessions.router,      prefix="/api/v1", tags=["📋 Sessions"])
app.include_router(skills.router,        prefix="/api/v1", tags=["🧠 Skills"])
app.include_router(tools.router,         prefix="/api/v1", tags=["🔧 Tools"])
app.include_router(config.router,        prefix="/api/v1", tags=["⚙️ Config"])
app.include_router(gateway.router,       prefix="/api/v1", tags=["🌐 Gateway"])
app.include_router(profiles.router,      prefix="/api/v1", tags=["👤 Profiles"])
app.include_router(files.router,         prefix="/api/v1", tags=["📁 Files"])
app.include_router(plugins.router,       prefix="/api/v1", tags=["🔌 Plugins"])
app.include_router(cron_routes.router,   prefix="/api/v1", tags=["⏰ Cron"])
app.include_router(system_routes.router, prefix="/api/v1", tags=["🖥️ System"])

# Kök health (hem /api/v1/health hem direkt)
@app.get("/api/v1/health", tags=["🖥️ System"])
async def health_root():
    return await system_routes.health()


# ── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
    ╔══════════════════════════════════════════════════════╗
    ║                  ⚔  FETIH API  ⚔                    ║
    ╠══════════════════════════════════════════════════════╣
    ║  Port      : {port:<6}                              ║
    ║  Host      : {host:<20}              ║
    ║  Swagger   : http://{host}:{port}/api/docs           ║
    ║  ReDoc     : http://{host}:{port}/api/redoc          ║
    ║  Health    : http://{host}:{port}/api/v1/health      ║
    ║  Endpoints : 69 (12 kategori)                        ║
    ╚══════════════════════════════════════════════════════╝
"""

# ── Ana giriş ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="FETIH REST API Server — 69 endpoint ile tam yönetim",
        epilog="Örnek: python3 api/server.py --port 1453"
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("FETIH_API_PORT", "1453")),
                        help="Sunucu portu (varsayılan: 1453)")
    parser.add_argument("--host", default=os.environ.get("FETIH_API_HOST", "127.0.0.1"),
                        help="Bind adresi (varsayılan: 127.0.0.1)")
    parser.add_argument("--reload", action="store_true",
                        help="Kod değişikliğinde otomatik yeniden başlat (development)")
    parser.add_argument("--log-level", default="info",
                        choices=["critical", "error", "warning", "info", "debug"],
                        help="Log seviyesi")
    args = parser.parse_args()

    print(BANNER.format(port=args.port, host=args.host))

    # Graceful shutdown
    def _shutdown(sig, frame):
        print("\n⚔ FETIH API kapatılıyor...")
        sys.exit(0)
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
        access_log=False,
        server_header=False,
        date_header=False,
    )

if __name__ == "__main__":
    main()

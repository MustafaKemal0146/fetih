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
import os, sys, time, logging, argparse
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


def _cors_origins() -> list[str]:
    """CORS origin'lerini env'den oku.

    FETIH_API_CORS_ORIGINS tanımlı değilse mevcut davranış korunur (tüm
    origin'lere açık). Virgülle ayrılmış liste verilebilir, örn:
        FETIH_API_CORS_ORIGINS="https://app.example.com,http://localhost:3000"
    """
    raw = os.environ.get("FETIH_API_CORS_ORIGINS", "").strip()
    if not raw or raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]

# ── FastAPI App ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("FETIH API v1 başlatıldı")
    yield
    # Graceful shutdown: çalışan arkaplan görevlerini işaretle ve sayımı logla.
    try:
        from api.routes.deps import _active_tasks
        running = [tid for tid, t in _active_tasks.items()
                   if t.get("status") in ("queued", "running")]
        if running:
            logger.warning("Shutdown: %d arkaplan görevi iptal ediliyor", len(running))
            for tid in running:
                _active_tasks[tid]["status"] = "cancelled"
    except Exception as e:
        logger.debug("Shutdown task cleanup atlandı: %s", e)
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

# CORS — varsayılan tüm origin'lere açık; FETIH_API_CORS_ORIGINS ile kısıtlanabilir.
# Not: tarayıcılar credentials ile "*" origin'i reddeder, bu yüzden açık modda
# allow_credentials=False; açık origin listesi verilince credentials açılır.
_origins = _cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Güvenlik header'ları — clickjacking/MIME-sniffing/referrer sızıntısına karşı.
@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response

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

    # Graceful shutdown: uvicorn kendi SIGINT/SIGTERM handler'larını kurar ve
    # lifespan shutdown'ını (arkaplan görev temizliği) tetikler. Manuel
    # sys.exit(0) handler'ı bu temizliği atladığı için kaldırıldı.
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

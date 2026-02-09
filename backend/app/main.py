"""FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from app.config import settings
from app.utils.logging import configure_logging, get_logger

configure_logging(settings.log_level)
log = get_logger("main")


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup / shutdown lifecycle hook."""
    log.info("soc_platform_starting", workers=settings.workers)
    # Import here to avoid circular deps
    from app.database import engine  # noqa: F401
    from app.services.scheduler import scheduler

    await scheduler.start()
    yield
    await scheduler.stop()
    log.info("soc_platform_stopped")


app = FastAPI(
    title="SOC Network Discovery Platform",
    description="Async 4-stage network scanning pipeline with real-time monitoring",
    version="1.0.0",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── CORS ────────────────────────────────────────
origins = [o.strip() for o in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global exception handler ───────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=str(request.url), error=str(exc), exc_info=True)
    return ORJSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )


# ── Health ──────────────────────────────────────
@app.get("/health", tags=["system"])
async def health_check():
    return {"status": "healthy", "service": "soc-api"}


# ── Register routers ───────────────────────────
from app.api.scans import router as scans_router      # noqa: E402
from app.api.hosts import router as hosts_router       # noqa: E402
from app.api.tags import router as tags_router         # noqa: E402
from app.api.export import router as export_router     # noqa: E402
from app.api.dashboard import router as dashboard_router  # noqa: E402
from app.api.ws import router as ws_router             # noqa: E402
from app.api.network import router as network_router   # noqa: E402

app.include_router(scans_router, prefix="/api")
app.include_router(hosts_router, prefix="/api")
app.include_router(tags_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(network_router, prefix="/api")
app.include_router(ws_router)

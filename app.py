"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    from core.database import init_db
    await init_db()
    yield
    # Shutdown
    from core.database import close_db
    from core.redis import close_redis
    await close_db()
    await close_redis()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate limiter
    from api.middleware.rate_limiter import RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware)

    # Routers
    from api.routes.auth import router as auth_router
    app.include_router(auth_router)

    # Health check
    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


app = create_app()
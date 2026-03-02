"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from aperture.api.routes import artifacts, audit, config, intelligence, permissions
from aperture.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aperture",
        description="The permission layer for AI agents. Controls what passes through.",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.include_router(permissions.router, prefix="/permissions", tags=["permissions"])
    app.include_router(artifacts.router, prefix="/artifacts", tags=["artifacts"])
    app.include_router(audit.router, prefix="/audit", tags=["audit"])
    app.include_router(intelligence.router, prefix="/intelligence", tags=["intelligence"])
    app.include_router(config.router, prefix="/config", tags=["config"])

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "aperture", "version": "0.2.0"}

    return app

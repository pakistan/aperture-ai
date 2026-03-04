"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from aiperture import plugins
from aiperture.api.auth import require_api_key
from aiperture.api.routes import artifacts, audit, config, health, intelligence, metrics, permissions
from aiperture.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    plugins.load_all()
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIperture",
        description="The permission layer for AI agents. Controls what passes through.",
        version="0.4.0",
        lifespan=lifespan,
        dependencies=[Depends(require_api_key)],
    )

    app.include_router(permissions.router, prefix="/permissions", tags=["permissions"])
    app.include_router(artifacts.router, prefix="/artifacts", tags=["artifacts"])
    app.include_router(audit.router, prefix="/audit", tags=["audit"])
    app.include_router(intelligence.router, prefix="/intelligence", tags=["intelligence"])
    app.include_router(config.router, prefix="/config", tags=["config"])
    app.include_router(health.router, tags=["health"])
    app.include_router(metrics.router, tags=["metrics"])

    # Register plugin routers if any
    plugin_router = plugins.get("router")
    if plugin_router is not None:
        for router_info in plugin_router.get_routers():
            app.include_router(router_info)

    return app

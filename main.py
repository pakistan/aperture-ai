"""Aperture server entry point."""

import os

import uvicorn

import aperture.config
from aperture.api import create_app

app = create_app()

if __name__ == "__main__":
    settings = aperture.config.settings
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=os.environ.get("APERTURE_DEBUG", "").lower() in ("1", "true"),
    )

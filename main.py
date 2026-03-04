"""Aperture server entry point."""

import logging
import os

import uvicorn

import aiperture.config
from aiperture.api import create_app

logging.basicConfig(
    level=getattr(logging, aiperture.config.settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [aiperture] %(levelname)s %(message)s",
)
aiperture.config.setup_file_logging()

app = create_app()

if __name__ == "__main__":
    settings = aiperture.config.settings
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=os.environ.get("AIPERTURE_DEBUG", "").lower() in ("1", "true"),
    )

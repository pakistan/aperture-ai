"""Configuration API — GET /config and PATCH /config for tunable settings."""

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import aperture.config

router = APIRouter()


class ConfigPatchRequest(BaseModel):
    settings: dict[str, Any]


@router.get("")
def get_config():
    """Return current tunable settings and their descriptions."""
    return {
        "settings": aperture.config.get_tunable_config(),
        "descriptions": dict(aperture.config.Settings.TUNABLE_DESCRIPTIONS),
    }


@router.patch("")
def patch_config(body: ConfigPatchRequest):
    """Update tunable settings at runtime. Persists to .aperture.env."""
    try:
        aperture.config.update_settings(body.settings)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "updated": True,
        "settings": aperture.config.get_tunable_config(),
    }

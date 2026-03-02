"""Test fixtures — fresh SQLite database per test."""

from pathlib import Path

import pytest

import aperture.config
from aperture.db.engine import get_engine, init_db, reset_engine


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Create a fresh SQLite database for each test."""
    db_path = tmp_path / "test.db"
    aperture.config.settings = aperture.config.Settings(
        db_path=str(db_path),
        artifact_storage_dir=str(tmp_path / "artifacts"),
    )
    reset_engine()
    init_db()
    yield
    reset_engine()

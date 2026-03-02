"""Database engine — lazy singleton, SQLite with WAL mode."""

import logging

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

import aperture.config

logger = logging.getLogger(__name__)

_engine = None


def _import_all_models():
    """Import all SQLModel table classes so metadata is populated."""
    import aperture.models.artifact  # noqa: F401
    import aperture.models.audit  # noqa: F401
    import aperture.models.intelligence  # noqa: F401
    import aperture.models.permission  # noqa: F401


def get_engine():
    """Get or create the database engine (lazy singleton)."""
    global _engine
    if _engine is not None:
        return _engine

    settings = aperture.config.settings

    if settings.db_backend == "postgres" and settings.postgres_url:
        url = settings.postgres_url
    else:
        url = f"sqlite:///{settings.db_path}"

    _engine = create_engine(url, echo=False)

    # Enable WAL mode for SQLite (better concurrent reads)
    if settings.db_backend == "sqlite":

        @event.listens_for(_engine, "connect")
        def _set_sqlite_wal(dbapi_conn, _):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return _engine


def get_session() -> Session:
    """Create a new database session."""
    return Session(get_engine())


def init_db():
    """Create all tables. Safe to call multiple times."""
    _import_all_models()
    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    logger.info("Database initialized")


def reset_engine():
    """Reset engine singleton. Used in tests."""
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None

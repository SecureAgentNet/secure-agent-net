"""Database engine/session management for the Cloud Console.

Independent from the per-host gateway DB. DB-agnostic: SQLite for local/dev,
PostgreSQL for the VPS deployment. Schema is owned by **Alembic migrations**
(``secureagentnet/cloud/migrations``) so an already-deployed console picks up
new columns/tables on upgrade — something ``create_all`` cannot do (it adds
missing tables but never ALTERs an existing one). ``create_all`` is retained
only as a last-resort fallback if migrations cannot run.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from secureagentnet.cloud.config import get_cloud_settings

logger = logging.getLogger("SecureAgentNet.Cloud.DB")

Base = declarative_base()

_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_cloud_settings()
        url = settings.resolved_database_url
        if url.startswith("sqlite"):
            settings.data_dir.mkdir(parents=True, exist_ok=True)
            _engine = create_engine(url, connect_args={"check_same_thread": False})
        else:
            _engine = create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20)
        logger.info("Cloud DB engine ready (%s)", _engine.url.get_backend_name())
    return _engine


def get_session_local():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionLocal


@contextmanager
def get_session():
    session = get_session_local()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _alembic_config():
    """Build an Alembic Config bound to the cloud migrations + resolved DB URL."""
    from alembic.config import Config

    here = Path(__file__).parent
    cfg = Config(str(here / "alembic.ini"))
    # Absolute paths so it works regardless of the process's cwd (uvicorn, tests).
    cfg.set_main_option("script_location", str(here / "migrations"))
    cfg.set_main_option("sqlalchemy.url", get_cloud_settings().resolved_database_url)
    return cfg


def run_migrations() -> None:
    """Upgrade the cloud DB to the latest schema revision (``alembic upgrade head``).

    Idempotent: safe to call on every startup. Handles fresh DBs, DBs previously
    created by ``create_all`` (adopted without a stamp), and already-current DBs.
    """
    from alembic import command

    # Ensure the SQLite parent dir exists before Alembic connects.
    settings = get_cloud_settings()
    if settings.resolved_database_url.startswith("sqlite"):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    command.upgrade(_alembic_config(), "head")


def init_db():
    from secureagentnet.cloud import models  # noqa: F401 — register models on Base
    try:
        run_migrations()
        logger.info("Cloud console schema migrated to head.")
    except Exception as exc:  # pragma: no cover — fallback for broken migration env
        logger.warning("Alembic migration failed (%s); falling back to create_all.", exc)
        Base.metadata.create_all(bind=get_engine())
        logger.info("Cloud console schema created/verified via create_all.")


def dispose_engine():
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionLocal = None

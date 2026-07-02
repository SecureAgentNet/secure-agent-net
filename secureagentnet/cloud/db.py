"""Database engine/session management for the Cloud Console.

Independent from the per-host gateway DB. DB-agnostic: SQLite for local/dev,
PostgreSQL for the VPS deployment. Uses the ORM's create_all (no raw schema),
mirroring the lesson from the gateway init fix.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager

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


def init_db():
    from secureagentnet.cloud import models  # noqa: F401 — register models on Base
    Base.metadata.create_all(bind=get_engine())
    logger.info("Cloud console schema created/verified.")


def dispose_engine():
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionLocal = None

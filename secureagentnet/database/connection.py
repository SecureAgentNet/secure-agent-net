import logging
from contextlib import contextmanager
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import QueuePool

from secureagentnet.core.config import get_settings

logger = logging.getLogger("SecureAgentNet.Database")

Base = declarative_base()

_engine = None
_SessionLocal = None


def _is_sqlite(url: str) -> bool:
    return url and url.startswith("sqlite")


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        url = settings.database_url
        if _is_sqlite(url):
            db_path = url.replace("sqlite:///", "")
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            _engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
            )
        else:
            _engine = create_engine(
                url,
                poolclass=QueuePool,
                pool_size=settings.database_pool_size,
                max_overflow=settings.database_max_overflow,
                pool_pre_ping=True,
                pool_recycle=3600,
            )
        logger.info(f"Database engine created for {url.split('@')[-1] if '@' in url else url}")
    return _engine


def get_session_local():
    global _SessionLocal
    if _SessionLocal is None:
        engine = get_engine()
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return _SessionLocal


@contextmanager
def get_db_session():
    SessionLocal = get_session_local()
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _add_missing_columns():
    """Add nullable columns that exist on a model but not yet in the database.

    ``create_all`` only creates missing *tables*; it never alters one that is
    already there. An endpoint that has been running since before a column was
    introduced would keep failing every query that touches it, so additive,
    nullable columns are reconciled here. Anything destructive (drops, type
    changes, NOT NULL) is deliberately out of scope and belongs in Alembic.
    """
    from sqlalchemy import inspect, text

    engine = get_engine()
    try:
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
    except Exception as exc:
        logger.debug("Could not inspect database for column reconciliation: %s", exc)
        return

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # create_all just built it, so it is already current
        try:
            present = {c["name"] for c in inspector.get_columns(table.name)}
        except Exception:
            continue
        for column in table.columns:
            if column.name in present or not column.nullable:
                continue
            ddl = (f"ALTER TABLE {table.name} ADD COLUMN {column.name} "
                   f"{column.type.compile(engine.dialect)}")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added missing column %s.%s", table.name, column.name)
            except Exception as exc:
                logger.warning("Could not add column %s.%s: %s", table.name, column.name, exc)


def init_database():
    from secureagentnet.database import models  # noqa: F401 — register models
    Base.metadata.create_all(bind=get_engine())
    _add_missing_columns()
    logger.info("Database tables created/verified.")


def dispose_engine():
    global _engine, _SessionLocal
    if _engine:
        _engine.dispose()
        _engine = None
        _SessionLocal = None
        logger.info("Database engine disposed.")

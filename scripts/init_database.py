#!/usr/bin/env python3
"""Initialize the SecureAgentNet database schema.

Uses the SQLAlchemy ORM models (``Base.metadata.create_all``), which are
backend-agnostic and create identical tables on SQLite, MariaDB/MySQL and
PostgreSQL. This is the same path the daemon uses at startup, so the CLI
setup step and the running service can never disagree about the schema.

PostgreSQL-only extras (e.g. full-text search triggers) live in
``secureagentnet/database/schema.sql`` and can be applied manually on Postgres
deployments that want them; they are intentionally not required for the
system to run.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import logging

from sqlalchemy import inspect

from secureagentnet.database.connection import get_engine, init_database as create_all_tables

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("SecureAgentNet.InitDB")


def init_database() -> bool:
    engine = get_engine()
    logger.info("Initializing schema on %s ...", engine.url.get_backend_name())

    # Registers all models and runs Base.metadata.create_all (idempotent).
    create_all_tables()

    tables = inspect(engine).get_table_names()
    logger.info("Schema ready — %d tables: %s", len(tables), ", ".join(sorted(tables)))
    return True


if __name__ == "__main__":
    try:
        ok = init_database()
    except Exception as exc:  # surface the real error instead of a bare crash
        logger.error("Database initialization failed: %s", exc)
        ok = False
    sys.exit(0 if ok else 1)

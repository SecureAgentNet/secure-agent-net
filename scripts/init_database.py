#!/usr/bin/env python3
"""Initialize the SecureAgentNet database schema."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import logging
from src.database.connection import get_engine
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureAgentNet.InitDB")


def init_database():
    schema_path = Path(__file__).parent.parent / "src" / "database" / "schema.sql"
    if not schema_path.exists():
        logger.error(f"Schema file not found at {schema_path}")
        return False

    engine = get_engine()
    schema_sql = schema_path.read_text()

    logger.info(f"Applying schema from {schema_path}...")
    with engine.connect() as conn:
        conn.execute(text(schema_sql))
        conn.commit()

    logger.info("Database schema applied successfully.")
    return True


if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)

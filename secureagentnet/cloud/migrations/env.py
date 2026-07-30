"""Alembic environment for the SecureAgentNet Cloud Console DB.

Separate from the per-host gateway's migration environment: this one targets
the console's own ``Base`` metadata and resolves its URL from CloudSettings,
so a single `upgrade head` works on SQLite (dev/demo) and PostgreSQL (VPS)
alike. Online mode reuses ``cloud.db.get_engine()`` so the console and its
migrations share connection settings (e.g. SQLite ``check_same_thread``).
"""
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context

# Make the package importable when Alembic is invoked from the CLI.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from secureagentnet.cloud.config import get_cloud_settings  # noqa: E402
from secureagentnet.cloud.db import Base, get_engine  # noqa: E402
from secureagentnet.cloud import models  # noqa: E402,F401 — register models on Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url") or get_cloud_settings().resolved_database_url
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = get_engine()
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Batch mode lets ALTER TABLE work on SQLite (used by the demo/dev DB).
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

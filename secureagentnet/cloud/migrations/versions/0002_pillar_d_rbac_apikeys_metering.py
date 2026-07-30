"""Pillar D: RBAC role, tenant API keys, and usage metering.

Adds the schema that turns the single-org console into a multi-tenant SaaS
surface:
  * ``admin_users.role`` — the owner/admin/operator/viewer RBAC column. Existing
    rows are back-filled to ``owner`` (they were the sole admin of their tenant).
  * ``api_keys`` — tenant-scoped programmatic keys for the read-only public API.
  * ``usage_counters`` — per-tenant, per-month metering (billing foundation).

This is the revision that closes the gap ``create_all`` left on already-deployed
databases: ``create_all`` adds *missing tables* but never ALTERs an existing one,
so a console upgraded in place would have kept an ``admin_users`` table with no
``role`` column. Every step here is guarded so it is safe on a fresh DB, a
pre-Pillar-D DB, and a DB where ``create_all`` already added the new tables.

Revision ID: 0002_pillar_d
Revises: 0001_baseline
Create Date: 2026-07-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_pillar_d"
down_revision: Union[str, Sequence[str], None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(name: str) -> bool:
    return name in _inspector().get_table_names()


def _has_column(table: str, column: str) -> bool:
    return any(c["name"] == column for c in _inspector().get_columns(table))


def upgrade() -> None:
    """Upgrade schema."""
    # 1) RBAC role on admin_users (back-fill existing admins as tenant owners).
    if _has_table("admin_users") and not _has_column("admin_users", "role"):
        op.add_column(
            "admin_users",
            sa.Column("role", sa.String(length=20), nullable=False,
                      server_default="owner"),
        )

    # 2) Tenant-scoped API keys for the public API / SDK.
    if not _has_table("api_keys"):
        op.create_table(
            "api_keys",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("tenant_id", sa.Uuid(),
                      sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("key_prefix", sa.String(length=16), nullable=False),
            sa.Column("key_hash", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=20), nullable=False,
                      server_default="viewer"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked", sa.Boolean(), nullable=True),
        )

    # 3) Per-tenant, per-month usage metering.
    if not _has_table("usage_counters"):
        op.create_table(
            "usage_counters",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("tenant_id", sa.Uuid(),
                      sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("period", sa.String(length=7), nullable=False),
            sa.Column("events_ingested", sa.Integer(), nullable=False,
                      server_default="0"),
            sa.Column("api_calls", sa.Integer(), nullable=False,
                      server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    """Downgrade schema."""
    if _has_table("usage_counters"):
        op.drop_table("usage_counters")
    if _has_table("api_keys"):
        op.drop_table("api_keys")
    if _has_table("admin_users") and _has_column("admin_users", "role"):
        with op.batch_alter_table("admin_users") as batch:
            batch.drop_column("role")

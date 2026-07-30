"""Cloud console baseline schema (pre-Pillar-D).

Captures the schema as it existed before multi-tenancy/RBAC (Pillar D): the
seven metadata-only tables the console launched with. Written to be
**idempotent** — every table creation is guarded — because production/demo
databases up to this point were created by ``Base.metadata.create_all`` and
were never stamped by Alembic. On such a database this revision no-ops each
existing table and simply records the version, so a plain ``upgrade head``
safely adopts an already-populated DB without touching its data.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    """Upgrade schema."""
    if not _has_table("tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("admin_users"):
        # NB: no `role` column here — that is added by 0002 (Pillar D RBAC).
        op.create_table(
            "admin_users",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("tenant_id", sa.Uuid(),
                      sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False, unique=True),
            sa.Column("password_hash", sa.String(length=255), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("enrollment_tokens"):
        op.create_table(
            "enrollment_tokens",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("tenant_id", sa.Uuid(),
                      sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(length=255), nullable=False),
            sa.Column("label", sa.String(length=200), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("used", sa.Boolean(), nullable=True),
        )

    if not _has_table("endpoints"):
        op.create_table(
            "endpoints",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("tenant_id", sa.Uuid(),
                      sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=False),
            sa.Column("platform", sa.String(length=100), nullable=True),
            sa.Column("api_key_hash", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=True),
            sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("agent_snapshots"):
        op.create_table(
            "agent_snapshots",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("endpoint_id", sa.Uuid(),
                      sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False),
            sa.Column("agent_ref", sa.String(length=255), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=True),
            sa.Column("type", sa.String(length=100), nullable=True),
            sa.Column("trust_score", sa.Float(), nullable=True),
            sa.Column("status", sa.String(length=20), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("events"):
        op.create_table(
            "events",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("endpoint_id", sa.Uuid(),
                      sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tenant_id", sa.Uuid(),
                      sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=True),
            sa.Column("decision", sa.String(length=20), nullable=True),
            sa.Column("risk_score", sa.Float(), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("agent_ref", sa.String(length=255), nullable=True),
            sa.Column("action_name", sa.String(length=150), nullable=True),
            sa.Column("target_type", sa.String(length=150), nullable=True),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("commands"):
        op.create_table(
            "commands",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("endpoint_id", sa.Uuid(),
                      sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False),
            sa.Column("type", sa.String(length=40), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False),
            sa.Column("issued_by", sa.String(length=255), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("result", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    """Downgrade schema."""
    for name in ("commands", "events", "agent_snapshots", "endpoints",
                 "enrollment_tokens", "admin_users", "tenants"):
        if _has_table(name):
            op.drop_table(name)

"""Cloud Console data model (multi-tenant aggregate).

UUID primary keys throughout: distributed-friendly and they avoid the
BigInteger-autoincrement-on-SQLite pitfall the gateway hit. Stores metadata
only — there is deliberately no column for raw action payloads or PII.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (Column, String, Text, Float, Boolean, DateTime,
                        ForeignKey, Uuid as _SAUuid)
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import relationship

from secureagentnet.cloud.db import Base


class Uuid(TypeDecorator):
    """UUID column that accepts a uuid.UUID or string on bind, so the same code
    persists on SQLite, MySQL/MariaDB and PostgreSQL."""
    impl = _SAUuid
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if isinstance(value, str):
            try:
                return uuid.UUID(value)
            except ValueError:
                return None
        return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    """An organisation that owns endpoints and admin users."""
    __tablename__ = "tenants"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)

    endpoints = relationship("Endpoint", back_populates="tenant", cascade="all, delete-orphan")
    admins = relationship("AdminUser", back_populates="tenant", cascade="all, delete-orphan")


class AdminUser(Base):
    """A console login. Passwords are stored as bcrypt hashes (see 3.2)."""
    __tablename__ = "admin_users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id = Column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)

    tenant = relationship("Tenant", back_populates="admins")


class EnrollmentToken(Base):
    """A one-time token an admin generates so a daemon can enrol (see 3.2)."""
    __tablename__ = "enrollment_tokens"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id = Column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False)
    label = Column(String(200), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    used = Column(Boolean, default=False)


class Endpoint(Base):
    """A host running a SecureAgentNet daemon, enrolled to a tenant."""
    __tablename__ = "endpoints"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id = Column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(100), nullable=True)
    api_key_hash = Column(String(255), nullable=False)
    status = Column(String(20), default="online")  # online | offline | suspended
    enrolled_at = Column(DateTime(timezone=True), default=_now)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="endpoints")
    agents = relationship("AgentSnapshot", back_populates="endpoint", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="endpoint", cascade="all, delete-orphan")
    commands = relationship("Command", back_populates="endpoint", cascade="all, delete-orphan")


class AgentSnapshot(Base):
    """Mirror of an agent's identity/trust as reported by an endpoint."""
    __tablename__ = "agent_snapshots"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    endpoint_id = Column(Uuid, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    agent_ref = Column(String(255), nullable=False)  # name or id as the endpoint knows it
    name = Column(String(255), nullable=True)
    type = Column(String(100), nullable=True)
    trust_score = Column(Float, nullable=True)
    status = Column(String(20), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=_now)

    endpoint = relationship("Endpoint", back_populates="agents")


class Event(Base):
    """A single reported security event — METADATA ONLY (no payloads, no PII)."""
    __tablename__ = "events"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    endpoint_id = Column(Uuid, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    kind = Column(String(20), nullable=False)        # decision | alert | audit
    severity = Column(String(20), nullable=True)      # INFO | WARNING | CRITICAL
    decision = Column(String(20), nullable=True)      # allow | deny | escalate
    risk_score = Column(Float, nullable=True)
    reason = Column(Text, nullable=True)
    agent_ref = Column(String(255), nullable=True)
    action_name = Column(String(150), nullable=True)
    target_type = Column(String(150), nullable=True)  # a category, never a concrete resource
    occurred_at = Column(DateTime(timezone=True), nullable=True)
    received_at = Column(DateTime(timezone=True), default=_now)

    endpoint = relationship("Endpoint", back_populates="events")


class Command(Base):
    """A control instruction queued for an endpoint (currently: kill-switch).

    Delivered by the daemon pulling it on its next heartbeat — nothing connects
    inbound to the endpoint."""
    __tablename__ = "commands"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    endpoint_id = Column(Uuid, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    type = Column(String(40), nullable=False, default="kill_switch")
    status = Column(String(20), nullable=False, default="pending")  # pending | acked | done | failed
    issued_by = Column(String(255), nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)
    acked_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(Text, nullable=True)

    endpoint = relationship("Endpoint", back_populates="commands")

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy import select, delete as sa_delete
from src.database.connection import get_db_session, get_engine, Base
from src.database import models
from src.utils.persistence import PersistenceStore as JsonStore


def init_db():
    """Create all tables. Safe to call repeatedly."""
    Base.metadata.create_all(bind=get_engine())


class AgentRepository:
    """DB-backed repository for agent identity data."""

    @classmethod
    def _agent_to_dict(cls, agent: models.Agent) -> dict:
        created_by = getattr(agent, 'created_by', 'system')
        return {
            "agent_id": str(agent.agent_id),
            "name": agent.name,
            "type": agent.type or "Custom",
            "description": agent.description or "",
            "public_key": agent.public_key or "",
            "registered_at": agent.registered_at.isoformat() if agent.registered_at else datetime.now(timezone.utc).isoformat(),
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "trust_score": agent.trust_score or 50.0,
            "status": agent.status or "active",
            "capabilities": agent.capabilities or {},
            "metadata": agent.metadata_ or {},
            "created_by": created_by,
        }

    @classmethod
    def _dict_to_agent(cls, data: dict) -> models.Agent:
        agent_id = data.get("agent_id")
        if agent_id and isinstance(agent_id, str):
            agent_id = uuid.UUID(agent_id)
        return models.Agent(
            agent_id=agent_id or uuid.uuid4(),
            name=data["name"],
            type=data.get("type", "Custom"),
            description=data.get("description", ""),
            public_key=data.get("public_key", ""),
            registered_at=_parse_dt(data.get("registered_at")) or datetime.now(timezone.utc),
            last_seen=_parse_dt(data.get("last_seen")),
            trust_score=data.get("trust_score", 50.0),
            status=data.get("status", "active"),
            capabilities=data.get("capabilities", {}),
            metadata_=data.get("metadata", {}),
            created_by=data.get("created_by", "system"),
        )

    @classmethod
    def load_all(cls) -> dict:
        agents: dict = {}
        try:
            with get_db_session() as session:
                rows = session.execute(select(models.Agent)).scalars().all()
                for row in rows:
                    agents[str(row.agent_id)] = cls._agent_to_dict(row)
        except Exception:
            agents = JsonStore.load("identity_registry", {}) or {}
        return agents

    @classmethod
    def save_all(cls, agents: dict):
        try:
            with get_db_session() as session:
                existing = {str(r.agent_id): r for r in session.execute(select(models.Agent)).scalars().all()}
                for agent_id_str, data in agents.items():
                    if agent_id_str in existing:
                        row = existing[agent_id_str]
                        row.name = data.get("name", row.name)
                        row.type = data.get("type", row.type)
                        row.description = data.get("description", row.description)
                        row.public_key = data.get("public_key", row.public_key)
                        row.trust_score = data.get("trust_score", row.trust_score)
                        row.status = data.get("status", row.status)
                        row.last_seen = _parse_dt(data.get("last_seen"))
                        row.capabilities = data.get("capabilities", row.capabilities)
                        row.metadata_ = data.get("metadata", row.metadata_)
                    else:
                        agent_data = {**data, "agent_id": agent_id_str}
                        session.add(cls._dict_to_agent(agent_data))
                gone = set(existing) - set(agents)
                for agent_id in gone:
                    session.execute(
                        sa_delete(models.Agent).where(models.Agent.agent_id == uuid.UUID(agent_id))
                    )
        except Exception:
            JsonStore.save("identity_registry", agents)

    @classmethod
    def save_one(cls, agent_id_str: str, data: dict):
        try:
            with get_db_session() as session:
                row = session.execute(
                    select(models.Agent).where(models.Agent.agent_id == uuid.UUID(agent_id_str))
                ).scalar_one_or_none()
                if row:
                    for k, v in data.items():
                        if k == "agent_id":
                            continue
                        if k == "metadata":
                            row.metadata_ = v
                        elif hasattr(row, k):
                            setattr(row, k, v)
                else:
                    session.add(cls._dict_to_agent({**data, "agent_id": agent_id_str}))
        except Exception:
            agents = JsonStore.load("identity_registry", {}) or {}
            agents[agent_id_str] = data
            JsonStore.save("identity_registry", agents)

    @classmethod
    def delete_one(cls, agent_id_str: str):
        try:
            with get_db_session() as session:
                session.execute(
                    sa_delete(models.Agent).where(models.Agent.agent_id == uuid.UUID(agent_id_str))
                )
        except Exception:
            agents = JsonStore.load("identity_registry", {}) or {}
            agents.pop(agent_id_str, None)
            JsonStore.save("identity_registry", agents)


class AuditLogRepository:
    """DB-backed repository for audit log entries."""

    @classmethod
    def load_all(cls) -> list:
        try:
            with get_db_session() as session:
                rows = session.execute(
                    select(models.AuditLogEntry).order_by(models.AuditLogEntry.timestamp.desc())
                ).scalars().all()
                return [{
                    "agent_id": str(r.agent_id) if r.agent_id else None,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "event_type": r.event_type,
                    "phase": r.phase,
                    "severity": r.severity,
                    "summary": r.summary,
                    "correlation_id": str(r.correlation_id) if r.correlation_id else None,
                    "vault_path": r.vault_path,
                } for r in rows]
        except Exception:
            return JsonStore.load("log_indexer", []) or []

    @classmethod
    def append(cls, entry: dict):
        try:
            with get_db_session() as session:
                agent_id = entry.get("agent_id")
                if agent_id and isinstance(agent_id, str):
                    agent_id = uuid.UUID(agent_id)
                correlation_id = entry.get("correlation_id")
                if correlation_id and isinstance(correlation_id, str):
                    correlation_id = uuid.UUID(correlation_id)
                log = models.AuditLogEntry(
                    agent_id=agent_id,
                    event_type=entry.get("event_type", "unknown"),
                    phase=entry.get("phase"),
                    severity=entry.get("severity", "INFO"),
                    summary=entry.get("summary"),
                    correlation_id=correlation_id,
                    vault_path=entry.get("vault_path"),
                )
                session.add(log)
        except Exception:
            events = JsonStore.load("log_indexer", []) or []
            events.append(entry)
            JsonStore.save("log_indexer", events)


class CircuitBreakerRepository:
    """DB-backed repository for circuit breaker state."""

    @classmethod
    def load_all(cls) -> dict:
        try:
            with get_db_session() as session:
                rows = session.execute(select(models.CircuitBreakerState)).scalars().all()
                result = {}
                for r in rows:
                    tripped = r.tripped_at.isoformat() if r.tripped_at else None
                    result[r.agent_id] = {
                        "failures": r.failures or [],
                        "state": r.state or "CLOSED",
                        "tripped_at": tripped,
                    }
                return result
        except Exception:
            return JsonStore.load("circuit_breaker", {}) or {}

    @classmethod
    def save_all(cls, state: dict):
        try:
            with get_db_session() as session:
                existing = {r.agent_id: r for r in session.execute(select(models.CircuitBreakerState)).scalars().all()}
                for agent_id, data in state.items():
                    if agent_id in existing:
                        row = existing[agent_id]
                        row.failures = data.get("failures", [])
                        row.state = data.get("state", "CLOSED")
                        row.tripped_at = _parse_dt(data.get("tripped_at"))
                    else:
                        session.add(models.CircuitBreakerState(
                            agent_id=agent_id,
                            failures=data.get("failures", []),
                            state=data.get("state", "CLOSED"),
                            tripped_at=_parse_dt(data.get("tripped_at")),
                        ))
                gone = set(existing) - set(state)
                for agent_id in gone:
                    session.execute(
                        sa_delete(models.CircuitBreakerState).where(
                            models.CircuitBreakerState.agent_id == agent_id
                        )
                    )
        except Exception:
            JsonStore.save("circuit_breaker", state)


class KillSwitchRepository:
    """DB-backed repository for kill-switch singleton state."""

    @classmethod
    def load(cls) -> dict:
        try:
            with get_db_session() as session:
                row = session.execute(select(models.KillSwitchState)).scalars().first()
                if row:
                    return {
                        "_armed": row.armed,
                        "_active": row.active,
                        "_trigger_count": row.trigger_count,
                        "_denial_counts": row.denial_counts or {},
                        "_last_triggered_at": row.last_triggered_at.isoformat() if row.last_triggered_at else None,
                        "_last_reset_at": row.last_reset_at.isoformat() if row.last_reset_at else None,
                        "_reset_by": row.reset_by,
                    }
                return {}
        except Exception:
            return JsonStore.load("kill_switch", {}) or {}

    @classmethod
    def save(cls, data: dict):
        try:
            with get_db_session() as session:
                row = session.execute(select(models.KillSwitchState)).scalars().first()
                if row:
                    row.armed = data.get("_armed", row.armed)
                    row.active = data.get("_active", row.active)
                    row.trigger_count = data.get("_trigger_count", row.trigger_count)
                    row.denial_counts = data.get("_denial_counts", row.denial_counts)
                    row.last_triggered_at = _parse_dt(data.get("_last_triggered_at"))
                    row.last_reset_at = _parse_dt(data.get("_last_reset_at"))
                    row.reset_by = data.get("_reset_by")
                else:
                    session.add(models.KillSwitchState(
                        armed=data.get("_armed", True),
                        active=data.get("_active", False),
                        trigger_count=data.get("_trigger_count", 0),
                        denial_counts=data.get("_denial_counts", {}),
                        last_triggered_at=_parse_dt(data.get("_last_triggered_at")),
                        last_reset_at=_parse_dt(data.get("_last_reset_at")),
                        reset_by=data.get("_reset_by"),
                    ))
        except Exception:
            JsonStore.save("kill_switch", data)


class ContainerRepository:
    """DB-backed repository for container records."""

    @classmethod
    def load_all(cls) -> dict:
        try:
            with get_db_session() as session:
                rows = session.execute(select(models.ContainerRecord)).scalars().all()
                result = {}
                for r in rows:
                    agent_id = str(r.agent_id) if r.agent_id else None
                    result[r.container_id] = {
                        "container_id": r.container_id,
                        "agent_id": agent_id,
                        "quota": {
                            "cpu_limit": r.cpu_limit or 1.0,
                            "memory_limit_mb": r.memory_limit_mb or 512,
                            "pids_limit": 50,
                        },
                        "status": r.status or "created",
                    }
                return result
        except Exception:
            return JsonStore.load("resource_manager", {}) or {}

    @classmethod
    def save_all(cls, containers: dict):
        try:
            with get_db_session() as session:
                existing = {r.container_id: r for r in session.execute(select(models.ContainerRecord)).scalars().all()}
                for cid, data in containers.items():
                    if cid in existing:
                        row = existing[cid]
                        row.status = data.get("status", row.status)
                        agent_id = data.get("agent_id")
                        if agent_id and isinstance(agent_id, str):
                            row.agent_id = uuid.UUID(agent_id)
                    else:
                        agent_id = data.get("agent_id")
                        if agent_id and isinstance(agent_id, str):
                            agent_id = uuid.UUID(agent_id)
                        else:
                            agent_id = None
                        quota = data.get("quota", {})
                        session.add(models.ContainerRecord(
                            container_id=cid,
                            agent_id=agent_id,
                            image=data.get("image", "unknown"),
                            status=data.get("status", "creating"),
                            cpu_limit=quota.get("cpu_limit"),
                            memory_limit_mb=quota.get("memory_limit_mb"),
                        ))
                gone = set(existing) - set(containers)
                for cid in gone:
                    session.execute(
                        sa_delete(models.ContainerRecord).where(
                            models.ContainerRecord.container_id == cid
                        )
                    )
        except Exception:
            JsonStore.save("resource_manager", containers)


def _parse_dt(val) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val)
        except (ValueError, TypeError):
            return None
    return None

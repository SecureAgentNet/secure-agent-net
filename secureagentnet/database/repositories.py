import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy import select, delete as sa_delete
from secureagentnet.database.connection import get_db_session, get_engine, Base
from secureagentnet.database import models
from secureagentnet.utils.persistence import PersistenceStore as JsonStore

logger = logging.getLogger("SecureAgentNet.Database.Repo")


def _is_uuid(value) -> bool:
    """True if value is a uuid.UUID or a string that parses as one."""
    if isinstance(value, uuid.UUID):
        return True
    if isinstance(value, str):
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False
    return False


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
        # The agent_id column is a UUID FK; a non-UUID identifier (an
        # unregistered or rogue agent) would coerce to NULL and lose the very
        # identity a forensic log must keep. Preserve it in the summary so a
        # blocked rogue action is never dropped from the audit trail.
        raw_agent = entry.get("agent_id")
        summary = entry.get("summary") or entry.get("event_type")
        if raw_agent and not _is_uuid(raw_agent):
            summary = f"[agent:{raw_agent}] {summary}"
            agent_id = None
        else:
            agent_id = raw_agent
        try:
            with get_db_session() as session:
                log = models.AuditLogEntry(
                    agent_id=agent_id,
                    event_type=entry.get("event_type", "unknown"),
                    phase=entry.get("phase"),
                    severity=entry.get("severity", "INFO"),
                    summary=summary,
                    correlation_id=entry.get("correlation_id"),
                    vault_path=entry.get("vault_path"),
                )
                session.add(log)
        except Exception as exc:
            # Never lose an audit record: fall back to the JSON store, but make
            # the failure visible rather than swallowing it silently.
            logger.warning("Audit DB write failed, using JSON fallback: %s", exc)
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


class MandateRepository:
    """DB-backed repository for agent mandates (the ``intent_capsules`` table).

    A mandate is an agent's commissioned goal plus the set of actions it is
    sanctioned to take. It is the anchor the DECIDE phase checks an action
    against to detect goal hijacking.
    """

    @classmethod
    def _row_to_dict(cls, r) -> dict:
        return {
            "session_id": str(r.session_id),
            "agent_id": str(r.agent_id) if r.agent_id else None,
            "user_id": r.user_id,
            "original_goal": r.original_goal,
            "approved_actions": r.approved_actions or [],
            "forbidden_actions": r.forbidden_actions or [],
            "created_at": r.created_at,
            "expires_at": r.expires_at,
            "active": bool(r.active),
        }

    @classmethod
    def get_active_for_agent(cls, agent_id: str) -> Optional[dict]:
        """Return the most recent active, unexpired mandate for an agent."""
        try:
            with get_db_session() as session:
                rows = session.execute(
                    select(models.IntentCapsule)
                    .where(models.IntentCapsule.agent_id == uuid.UUID(agent_id))
                    .where(models.IntentCapsule.active.is_(True))
                ).scalars().all()
                dicts = [cls._row_to_dict(r) for r in rows]
        except Exception:
            return None
        now = datetime.now(timezone.utc)
        live = [d for d in dicts if cls._aware(d["expires_at"]) > now]
        if not live:
            return None
        live.sort(key=lambda d: cls._aware(d["created_at"]), reverse=True)
        return live[0]

    @classmethod
    def save(cls, mandate: dict):
        """Insert or update a mandate row keyed by session_id."""
        try:
            with get_db_session() as session:
                sid = uuid.UUID(str(mandate["session_id"]))
                row = session.get(models.IntentCapsule, sid)
                agent_id = mandate.get("agent_id")
                agent_uuid = uuid.UUID(agent_id) if agent_id else None
                if row is None:
                    session.add(models.IntentCapsule(
                        session_id=sid,
                        agent_id=agent_uuid,
                        user_id=mandate.get("user_id", "system"),
                        original_goal=mandate["original_goal"],
                        approved_actions=mandate.get("approved_actions", []),
                        forbidden_actions=mandate.get("forbidden_actions", []),
                        created_at=cls._aware(mandate.get("created_at")) or datetime.now(timezone.utc),
                        expires_at=cls._aware(mandate["expires_at"]),
                        active=mandate.get("active", True),
                    ))
                else:
                    row.agent_id = agent_uuid
                    row.user_id = mandate.get("user_id", row.user_id)
                    row.original_goal = mandate["original_goal"]
                    row.approved_actions = mandate.get("approved_actions", [])
                    row.forbidden_actions = mandate.get("forbidden_actions", [])
                    row.expires_at = cls._aware(mandate["expires_at"])
                    row.active = mandate.get("active", True)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Failed to persist mandate: %s", e)

    @classmethod
    def deactivate_for_agent(cls, agent_id: str):
        """Retire all active mandates for an agent (used when re-commissioning)."""
        try:
            with get_db_session() as session:
                rows = session.execute(
                    select(models.IntentCapsule)
                    .where(models.IntentCapsule.agent_id == uuid.UUID(agent_id))
                    .where(models.IntentCapsule.active.is_(True))
                ).scalars().all()
                for r in rows:
                    r.active = False
        except Exception:
            pass

    @staticmethod
    def _aware(val) -> Optional[datetime]:
        """Coerce a value to a timezone-aware datetime (DB may return naive)."""
        dt = _parse_dt(val)
        if dt is not None and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt


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

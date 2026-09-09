import uuid
from datetime import datetime, timezone
from sqlalchemy import (Column, String, Text, Integer, Float, Boolean,
                        DateTime, JSON, Enum, BigInteger, LargeBinary,
                        SmallInteger, ForeignKey, UniqueConstraint,
                        CheckConstraint, Index, Uuid as _SAUuid)
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import relationship
from secureagentnet.database.connection import Base


class Uuid(TypeDecorator):
    """UUID column that transparently accepts a ``uuid.UUID`` *or* a string on
    bind, so identical code persists on PostgreSQL (native uuid), MariaDB/MySQL
    (CHAR(32)) and SQLite. Postgres coerced UUID strings silently; the non-native
    backends do not, so we coerce here. A non-UUID string (e.g. a ``corr-…``
    correlation id) is stored as NULL rather than crashing the whole insert.
    """
    impl = _SAUuid
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if isinstance(value, str):
            try:
                return uuid.UUID(value)
            except ValueError:
                return None
        return value


class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    type = Column(String(100), nullable=False, default="Custom")
    description = Column(Text, default="")
    public_key = Column(Text, default="")
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), nullable=True)
    trust_score = Column(Float, default=50.0)
    status = Column(String(20), default="active")
    capabilities = Column(JSON, default={})
    metadata_ = Column("metadata", JSON, default={})
    created_by = Column(String(255), default="system")

    capabilities_rel = relationship("AgentCapability", back_populates="agent", cascade="all, delete-orphan")


class AgentCapability(Base):
    __tablename__ = "agent_capabilities"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False)
    capability_name = Column(String(100), nullable=False)
    capability_level = Column(Integer, default=0)
    is_allowed = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    agent = relationship("Agent", back_populates="capabilities_rel")

    __table_args__ = (
        UniqueConstraint("agent_id", "capability_name", name="uq_agent_capability"),
    )


class AuditLogEntry(Base):
    __tablename__ = "audit_log_index"

    log_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    event_type = Column(String(100), nullable=False)
    phase = Column(String(20), nullable=True)
    severity = Column(String(20), default="INFO")
    vault_path = Column(Text, nullable=True)
    correlation_id = Column(Uuid, nullable=True)
    summary = Column(Text, nullable=True)


class CircuitBreakerState(Base):
    __tablename__ = "circuit_breaker_state"

    agent_id = Column(String(64), primary_key=True)
    failures = Column(JSON, default=list)
    state = Column(String(20), nullable=False, default="CLOSED")
    tripped_at = Column(DateTime(timezone=True), nullable=True)


class KillSwitchState(Base):
    __tablename__ = "kill_switch_state"

    id = Column(SmallInteger, primary_key=True, default=1)
    armed = Column(Boolean, default=True)
    active = Column(Boolean, default=False)
    trigger_count = Column(Integer, default=0)
    denial_counts = Column(JSON, default={})
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    last_reset_at = Column(DateTime(timezone=True), nullable=True)
    reset_by = Column(String(255), nullable=True)

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_kill_switch_singleton"),
    )


class ContainerRecord(Base):
    __tablename__ = "containers"

    container_id = Column(String(64), primary_key=True)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=True)
    image = Column(String(255), nullable=False)
    status = Column(String(20), default="creating")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True), nullable=True)
    stopped_at = Column(DateTime(timezone=True), nullable=True)
    exit_code = Column(Integer, nullable=True)
    cpu_limit = Column(Float, nullable=True)
    memory_limit_mb = Column(Integer, nullable=True)
    network_mode = Column(String(50), nullable=True)
    read_only_root = Column(Boolean, default=True)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    action_type = Column(String(20), nullable=False, default="deny")
    conditions = Column(JSON, nullable=False, default={})
    priority = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


class AuthEvent(Base):
    __tablename__ = "auth_events"

    event_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=True)
    event_type = Column(String(50), nullable=False)
    challenge_nonce = Column(LargeBinary, nullable=True)
    signature = Column(LargeBinary, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    success = Column(Boolean, nullable=True)
    failure_reason = Column(Text, nullable=True)


class ReasoningLog(Base):
    __tablename__ = "reasoning_logs"

    log_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=True)
    session_id = Column(Uuid, nullable=False)
    input_prompt = Column(Text, nullable=True)
    reasoning_steps = Column(Text, nullable=True)
    final_decision = Column(Text, nullable=True)
    confidence_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DecisionLog(Base):
    __tablename__ = "decision_log"

    decision_id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=True)
    session_id = Column(Uuid, nullable=False)
    request_hash = Column(LargeBinary, nullable=True)
    tier1_result = Column(String(10), nullable=True)
    tier2_pii_count = Column(Integer, default=0)
    tier2_entities = Column(JSON, nullable=True)
    tier3_safe = Column(Boolean, nullable=True)
    tier3_confidence = Column(Float, nullable=True)
    tier3_threats = Column(JSON, nullable=True)
    tier3_reasoning = Column(Text, nullable=True)
    final_decision = Column(String(20), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    processing_time_ms = Column(Integer, nullable=True)


class IntentCapsule(Base):
    __tablename__ = "intent_capsules"

    session_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=True)
    user_id = Column(String(255), nullable=False)
    original_goal = Column(Text, nullable=False)
    approved_actions = Column(JSON, default=[])
    forbidden_actions = Column(JSON, default=[])
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    active = Column(Boolean, default=True)


class HITLRequest(Base):
    """A medium-risk action parked for operator approval.

    Persisted rather than held in process memory: the escalating process (a
    one-shot ``san run``) and the resolving process (``san hitl approve``, the
    daemon API, the desktop console) are different processes, so an in-memory
    queue is invisible to every consumer but its own.
    """

    __tablename__ = "hitl_requests"

    request_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=True)
    action_name = Column(String(255), nullable=False)
    target_resource = Column(Text, nullable=True)
    intent_summary = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=True)
    reason = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    decision_at = Column(DateTime(timezone=True), nullable=True)
    decided_by = Column(String(255), nullable=True)
    # Stable identity of the action that was escalated: agent + action + target +
    # payload. A re-issued action hashes to the same value, which is how an
    # operator's approval is matched back to the retry that should execute under it.
    request_fingerprint = Column(String(64), nullable=True)
    # Set when a decision has been spent on one execution. A decision is
    # single-use: approving once does not permanently whitelist the action.
    consumed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_hitl_requests_status", "status"),
        Index("ix_hitl_requests_fingerprint", "request_fingerprint"),
    )


class User(Base):
    __tablename__ = "users"

    user_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(20), default="viewer")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)
    active = Column(Boolean, default=True)


class BlogPost(Base):
    __tablename__ = "blog_posts"

    post_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    summary = Column(Text, nullable=True)
    content = Column(Text, nullable=False)
    author = Column(String(100), nullable=False)
    tags = Column(JSON, default=[])
    read_time = Column(String(20), default="5 MIN")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    published = Column(Boolean, default=True)


class AgentRun(Base):
    """One commissioned run of an agent, start to finish.

    The row is the answerable record of a job: what the operator asked for, the
    mandate they approved, what the agent produced, and how the gateway ruled on
    the way. ``agent_id`` is nullable and set to NULL rather than cascaded on
    agent deletion — deleting an agent must not delete the evidence of what it
    did while it existed.
    """

    __tablename__ = "agent_runs"

    run_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id = Column(Uuid, ForeignKey("agents.agent_id", ondelete="SET NULL"), nullable=True)
    agent_key = Column(String(64), nullable=False)
    agent_name = Column(String(255), nullable=False)
    operator = Column(String(255), nullable=True)

    prompt = Column(Text, nullable=False)
    task = Column(Text, nullable=True)
    goal = Column(Text, nullable=False)
    approved_actions = Column(JSON, default=[])
    forbidden_actions = Column(JSON, default=[])

    status = Column(String(20), nullable=False, default="running")
    brain = Column(String(120), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True), nullable=True)
    final_answer = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    artifacts = Column(JSON, default=[])

    allowed_count = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    escalated_count = Column(Integer, default=0)
    # {entity_type: times_masked} for content the agent read. The tally is kept;
    # the values themselves never were.
    redactions = Column(JSON, default={})

    __table_args__ = (
        Index("ix_agent_runs_started_at", "started_at"),
        Index("ix_agent_runs_agent_id", "agent_id"),
    )


class AgentRunEvent(Base):
    """One thing that happened during a run, in the order it happened.

    Kept as rows rather than a JSON blob on the run so a question like "show me
    every action this agent was blocked from taking" is a query, not a scan of
    every run's payload.
    """

    __tablename__ = "agent_run_events"

    event_id = Column(BigInteger().with_variant(Integer, "sqlite"),
                      primary_key=True, autoincrement=True)
    run_id = Column(Uuid, ForeignKey("agent_runs.run_id", ondelete="CASCADE"),
                    nullable=False)
    seq = Column(Integer, nullable=False)
    kind = Column(String(32), nullable=False)
    summary = Column(Text, nullable=True)
    verdict = Column(String(16), nullable=True)
    at = Column(DateTime(timezone=True), nullable=False,
                default=lambda: datetime.now(timezone.utc))
    detail = Column(JSON, default={})

    __table_args__ = (
        Index("ix_agent_run_events_run_seq", "run_id", "seq"),
        Index("ix_agent_run_events_verdict", "verdict"),
    )

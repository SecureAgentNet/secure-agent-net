"""The daemon↔console wire contract — one source of truth for both sides.

Every model uses ``extra="forbid"``: the metadata allowlist is enforced
structurally, so a report that carries a raw payload or PII field is *rejected*
(HTTP 422), not silently accepted. This is what makes "metadata only" a
guarantee rather than a convention. The daemon's reporter (3.4) builds its
outbound payloads from these same models.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict

# The complete set of fields a reported event may carry. Anything else is barred.
ALLOWED_EVENT_FIELDS = frozenset({
    "kind", "severity", "decision", "risk_score", "reason",
    "agent_ref", "action_name", "target_type", "occurred_at",
})


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str                                  # decision | alert | audit
    severity: Optional[str] = None             # INFO | WARNING | CRITICAL
    decision: Optional[str] = None             # allow | deny | escalate
    risk_score: Optional[float] = None
    reason: Optional[str] = None
    agent_ref: Optional[str] = None
    action_name: Optional[str] = None
    target_type: Optional[str] = None          # a category, never a concrete resource/path
    occurred_at: Optional[datetime] = None


class AgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_ref: str
    name: Optional[str] = None
    type: Optional[str] = None
    trust_score: Optional[float] = None
    status: Optional[str] = None


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: List[EventIn] = []
    agents: List[AgentIn] = []


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agents: List[AgentIn] = []
    threats_blocked: Optional[int] = None


class CommandOut(BaseModel):
    id: str
    type: str
    reason: Optional[str] = None


class HeartbeatResponse(BaseModel):
    server_time: str
    commands: List[CommandOut] = []


class IngestResponse(BaseModel):
    accepted_events: int
    accepted_agents: int

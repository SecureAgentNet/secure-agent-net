"""Data-plane routes: endpoints push metadata events here and heartbeat.

Authenticated by the per-daemon API key (X-SAN-Endpoint-Key). Stores metadata
only; the wire models in protocol.py forbid any non-allowlisted field.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from secureagentnet.cloud import models
from secureagentnet.cloud.db import get_session
from secureagentnet.cloud.deps import require_endpoint
from secureagentnet.cloud.metering import record_usage
from secureagentnet.cloud.protocol import (AgentIn, HeartbeatRequest,
                                           HeartbeatResponse, IngestRequest,
                                           IngestResponse, CommandOut)

router = APIRouter(prefix="/api/v1", tags=["ingest"])


def _upsert_agents(session, endpoint_id, tenant_unused, agents: list[AgentIn]) -> int:
    n = 0
    for a in agents:
        snap = session.execute(
            select(models.AgentSnapshot).where(
                models.AgentSnapshot.endpoint_id == endpoint_id,
                models.AgentSnapshot.agent_ref == a.agent_ref,
            )
        ).scalar_one_or_none()
        if snap is None:
            snap = models.AgentSnapshot(endpoint_id=endpoint_id, agent_ref=a.agent_ref)
            session.add(snap)
        snap.name = a.name
        snap.type = a.type
        snap.trust_score = a.trust_score
        snap.status = a.status
        snap.updated_at = datetime.now(timezone.utc)
        n += 1
    return n


@router.post("/ingest", response_model=IngestResponse)
def ingest(req: IngestRequest, endpoint: models.Endpoint = Depends(require_endpoint)):
    now = datetime.now(timezone.utc)
    with get_session() as s:
        ep = s.get(models.Endpoint, endpoint.id)
        for e in req.events:
            s.add(models.Event(
                endpoint_id=ep.id,
                tenant_id=ep.tenant_id,
                kind=e.kind,
                severity=e.severity,
                decision=e.decision,
                risk_score=e.risk_score,
                reason=e.reason,
                agent_ref=e.agent_ref,
                action_name=e.action_name,
                target_type=e.target_type,
                occurred_at=e.occurred_at,
                received_at=now,
            ))
        n_agents = _upsert_agents(s, ep.id, ep.tenant_id, req.agents)
        ep.last_heartbeat = now
        ep.status = "online"
        # Meter ingested events for per-tenant billing (best-effort).
        try:
            record_usage(s, ep.tenant_id, events=len(req.events))
        except Exception:  # noqa: BLE001 - metering must never block ingest
            pass
    return IngestResponse(accepted_events=len(req.events), accepted_agents=n_agents)


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(req: HeartbeatRequest, endpoint: models.Endpoint = Depends(require_endpoint)):
    now = datetime.now(timezone.utc)
    commands: list[CommandOut] = []
    with get_session() as s:
        ep = s.get(models.Endpoint, endpoint.id)
        ep.last_heartbeat = now
        ep.status = "online"
        _upsert_agents(s, ep.id, ep.tenant_id, req.agents)
        # Pending commands (e.g. remote kill-switch) are delivered here and
        # marked delivered. The execution state machine is completed in 3.5.
        pending = s.execute(
            select(models.Command).where(
                models.Command.endpoint_id == ep.id,
                models.Command.status == "pending",
            )
        ).scalars().all()
        for c in pending:
            commands.append(CommandOut(id=str(c.id), type=c.type, reason=c.reason))
            c.status = "acked"
            c.acked_at = now
    return HeartbeatResponse(server_time=now.isoformat(), commands=commands)


class AckRequest(BaseModel):
    status: str            # done | failed
    result: str | None = None


@router.post("/commands/{command_id}/ack")
def ack_command(command_id: str, req: AckRequest,
                endpoint: models.Endpoint = Depends(require_endpoint)):
    """An endpoint reports the outcome of a command it executed. Scoped: an
    endpoint can only ack its own commands."""
    with get_session() as s:
        cmd = s.execute(
            select(models.Command).where(
                models.Command.id == command_id,
                models.Command.endpoint_id == endpoint.id,
            )
        ).scalar_one_or_none()
        if cmd is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Command not found")
        final = "done" if req.status == "done" else "failed"
        cmd.status = final
        cmd.result = (req.result or "")[:1000]
        cmd.acked_at = datetime.now(timezone.utc)
    return {"ok": True, "status": final}


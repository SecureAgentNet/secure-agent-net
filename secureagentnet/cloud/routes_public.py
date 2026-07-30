"""Public API for the Cloud Console — the surface a customer's own code / SDK
builds on. Authenticated by a tenant-scoped API key (``Authorization: Bearer
sank_...``), scoped to that tenant, and read-only. Every call is metered
(see require_api_key). Roles: any valid key may read.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select

from secureagentnet.cloud import models
from secureagentnet.cloud.db import get_session
from secureagentnet.cloud.deps import require_api_key

router = APIRouter(prefix="/api/v1/public", tags=["public-api"])


def _iso(dt):
    return dt.isoformat() if dt else None


@router.get("/events")
def list_events(auth: dict = Depends(require_api_key),
                severity: Optional[str] = None, limit: int = 100):
    """Recent security events for the caller's tenant (metadata only)."""
    limit = max(1, min(limit, 500))
    with get_session() as s:
        stmt = select(models.Event).where(models.Event.tenant_id == auth["tenant_id"])
        if severity:
            stmt = stmt.where(models.Event.severity == severity.upper())
        stmt = stmt.order_by(models.Event.received_at.desc()).limit(limit)
        rows = s.execute(stmt).scalars().all()
        return [{
            "id": str(e.id), "kind": e.kind, "severity": e.severity,
            "decision": e.decision, "risk_score": e.risk_score, "reason": e.reason,
            "agent_ref": e.agent_ref, "action_name": e.action_name,
            "received_at": _iso(e.received_at),
        } for e in rows]


@router.get("/agents")
def list_agents(auth: dict = Depends(require_api_key)):
    """Agent inventory (with trust scores) across the caller's tenant."""
    with get_session() as s:
        rows = s.execute(
            select(models.AgentSnapshot)
            .join(models.Endpoint, models.AgentSnapshot.endpoint_id == models.Endpoint.id)
            .where(models.Endpoint.tenant_id == auth["tenant_id"])
        ).scalars().all()
        return [{
            "agent_ref": a.agent_ref, "name": a.name, "type": a.type,
            "trust_score": a.trust_score, "status": a.status,
            "updated_at": _iso(a.updated_at),
        } for a in rows]

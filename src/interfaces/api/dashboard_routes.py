"""Operator-console support endpoints: agent inventory + kill-switch control.

Read endpoints are open (consistent with the existing /health and /hitl reads);
the kill-switch mutations are guarded by ``get_current_operator``.
"""
from fastapi import APIRouter, Depends

from src.interfaces.api.auth import get_current_operator

router = APIRouter(prefix="/api/v1", tags=["Operator Console"])


@router.get("/agents")
async def list_agents():
    from src.identify.identity_registry import IdentityRegistry

    agents = IdentityRegistry.list_agents()
    return {
        "total": len(agents),
        "active": sum(1 for a in agents if a.get("status") == "active"),
        "agents": [
            {
                "agent_id": str(a.get("agent_id")),
                "name": a.get("name"),
                "type": a.get("type"),
                "status": a.get("status"),
                "trust_score": a.get("trust_score"),
                "last_seen": a.get("last_seen"),
            }
            for a in agents
        ],
    }


@router.get("/security/status")
async def security_status():
    from src.decide.kill_switch import KillSwitchController
    from src.identify.identity_registry import IdentityRegistry
    from src.track.log_indexer import LogIndexer

    ks = KillSwitchController()
    return {
        "kill_switch": ks.get_status(),
        "agents_total": IdentityRegistry.get_total_count(),
        "agents_active": IdentityRegistry.get_active_count(),
        "events_indexed": len(LogIndexer._events),
    }


@router.post("/security/kill-switch/activate")
async def activate_kill_switch(operator: dict = Depends(get_current_operator)):
    from src.decide.kill_switch import KillSwitchController

    ks = KillSwitchController()
    ks.activate(triggered_by=operator.get("username", "operator"))
    return {"status": "activated", "kill_switch": ks.get_status()}


@router.post("/security/kill-switch/deactivate")
async def deactivate_kill_switch(operator: dict = Depends(get_current_operator)):
    from src.decide.kill_switch import KillSwitchController

    ks = KillSwitchController()
    ks.deactivate(reset_by=operator.get("username", "operator"))
    return {"status": "deactivated", "kill_switch": ks.get_status()}
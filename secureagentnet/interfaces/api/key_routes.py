import logging
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from secureagentnet.database.connection import get_db_session
from secureagentnet.database.models import Agent, AuthEvent
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.interfaces.api.auth import get_current_operator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/security-keys", tags=["Security Keys"])


class SecurityKeyResponse(BaseModel):
    agent_id: str
    agent_name: str
    public_key_hash: str
    status: str
    trust_score: float
    created_at: Optional[str] = None
    last_auth: Optional[str] = None
    auth_count: int = 0

    class Config:
        from_attributes = True


class KeyNonceRequest(BaseModel):
    agent_name: str


class RegisterKeyRequest(BaseModel):
    agent_name: str
    public_key: str
    agent_type: str = "Custom"


class RevokeKeyRequest(BaseModel):
    agent_id: str


def _serialize_key(agent: dict, auth_count: int, last_auth: Optional[datetime]) -> dict:
    return {
        "agent_id": agent.get("agent_id", ""),
        "agent_name": agent.get("name", "unknown"),
        "public_key_hash": agent.get("public_key", "")[:16] + "..." if agent.get("public_key") else "N/A",
        "status": agent.get("status", "unknown"),
        "trust_score": agent.get("trust_score", 0.0),
        "created_at": agent.get("created_at"),
        "last_auth": last_auth.isoformat() if last_auth else None,
        "auth_count": auth_count,
    }


@router.get("", response_model=list[SecurityKeyResponse])
def list_security_keys(_operator: dict = Depends(get_current_operator)):
    import uuid
    agents = IdentityRegistry.list_agents()
    result = []
    with get_db_session() as session:
        for agent in agents:
            agent_id = agent.get("agent_id", "")
            try:
                agent_uuid = uuid.UUID(agent_id) if agent_id else None
            except ValueError:
                agent_uuid = None
            auth_events = session.query(AuthEvent).filter(
                AuthEvent.agent_id == agent_uuid
            ).order_by(AuthEvent.timestamp.desc()).limit(1).all()
            last_auth = auth_events[0].timestamp if auth_events else None
            count = session.query(AuthEvent).filter(AuthEvent.agent_id == agent_uuid).count()
            result.append(_serialize_key(agent, count, last_auth))
    return result


@router.post("/nonce", status_code=201)
def generate_key_nonce(body: KeyNonceRequest, _operator: dict = Depends(get_current_operator)):
    import secrets
    agent = IdentityRegistry.get_agent_by_name(body.agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    nonce = secrets.token_hex(16)
    IdentityRegistry.update_agent(agent["agent_id"], {"_challenge_nonce": nonce})

    return {"agent_id": agent["agent_id"], "nonce": nonce, "expires_in_seconds": 300}


@router.post("/register", status_code=201)
def register_public_key(body: RegisterKeyRequest, _operator: dict = Depends(get_current_operator)):
    existing = IdentityRegistry.get_agent_by_name(body.agent_name)
    if existing:
        raise HTTPException(status_code=409, detail="Agent name already registered")

    agent_data = {
        "name": body.agent_name,
        "type": body.agent_type,
        "public_key": body.public_key,
        "capabilities": {"level": "operator", "actions": ["read"]},
        "metadata": {"registered_by": "admin_console"},
        "created_by": "console",
    }
    agent = IdentityRegistry.register_agent(agent_data)
    agent_id = agent.get("agent_id", "")

    logger.info("Registered new agent key: %s (%s)", body.agent_name, agent_id)
    return {
        "agent_id": agent_id,
        "agent_name": body.agent_name,
        "status": "active",
        "message": "Key registered successfully",
    }


@router.delete("/{agent_id}", status_code=204)
def revoke_key(agent_id: str, _operator: dict = Depends(get_current_operator)):
    agent = IdentityRegistry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    IdentityRegistry.revoke_agent(agent_id)
    logger.info("Revoked agent key: %s", agent_id)

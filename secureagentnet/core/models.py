import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


# --- Enums ---

class AgentStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ROGUE = "rogue"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


# --- Base Models (for creation, without ID or timestamps) ---

class AgentBase(BaseModel):
    name: str = Field(..., description="The human-readable name of the agent.")
    description: Optional[str] = Field(None, description="A brief description of the agent's purpose.")
    public_key: str = Field(..., description="The public key used to verify the agent's identity.")


class CapabilityBase(BaseModel):
    agent_id: uuid.UUID
    capability_name: str = Field(..., description="The name of the tool or action this agent can perform.")
    is_allowed: bool = True


class PolicyBase(BaseModel):
    name: str = Field(..., description="The name of the security policy.")
    description: Optional[str] = None
    action_type: PolicyAction
    conditions: Dict[str, Any] = Field(..., description="JSONB field for complex rule conditions.")


class AuditLogBase(BaseModel):
    agent_id: uuid.UUID
    action_requested: str
    resource_target: Optional[str] = None
    intent_summary: Optional[str] = None
    llm_risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    decision: str
    execution_time_ms: Optional[int] = None


# --- Database Models (with ID and timestamps for reading from DB) ---

class Agent(AgentBase):
    id: uuid.UUID
    status: AgentStatus = AgentStatus.ACTIVE
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AgentCapability(CapabilityBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


class Policy(PolicyBase):
    id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLog(AuditLogBase):
    id: uuid.UUID
    timestamp: datetime

    class Config:
        from_attributes = True


# --- API Models (for request/response payloads) ---

class AgentCreate(AgentBase):
    """Model for creating a new agent."""
    pass


class AgentDetails(Agent):
    """Full agent details including capabilities."""
    capabilities: List[AgentCapability] = []


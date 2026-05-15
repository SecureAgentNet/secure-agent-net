from pydantic import BaseModel, Field
from typing import Any, Dict, Optional
import uuid
from datetime import datetime


class AgentActionRequest(BaseModel):
    """The payload an agent submits when attempting to execute a tool or action."""
    action_name: str = Field(..., description="The name of the tool or action (e.g., 'execute_sql').")
    target_resource: str = Field(..., description="The resource being accessed (e.g., 'users_table').")
    intent_summary: str = Field(..., description="The agent's explanation of WHY it is doing this.")
    payload: Dict[str, Any] = Field(default_factory=dict, description="The actual parameters for the action.")


class CapturedLog(BaseModel):
    """The structured log event that will be stored."""
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action_request: AgentActionRequest
    risk_score: Optional[float] = None
    decision: str = "pending"
    vault_receipt_id: Optional[str] = None

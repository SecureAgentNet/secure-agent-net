from pydantic import BaseModel, Field
from typing import Dict, Any, List


class EvaluationRequest(BaseModel):
    """The request sent to the Decide phase to evaluate an agent's intent."""
    agent_id: str
    action_name: str
    target_resource: str
    intent_summary: str
    payload: Dict[str, Any]


class EvaluationResult(BaseModel):
    """The final decision from the 3-tier evaluation pipeline."""
    is_allowed: bool
    risk_score: float = Field(..., ge=0.0, le=1.0, description="0.0 is completely safe, 1.0 is definitely malicious.")
    reason: str
    evaluated_by: str = Field(..., description="Which tier made the final decision (e.g., 'RuleFilter', 'SemanticEvaluator').")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata (e.g., HITL request ID)")

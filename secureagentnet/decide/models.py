from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional


class EvaluationRequest(BaseModel):
    """The request sent to the Decide phase to evaluate an agent's intent."""
    agent_id: str
    action_name: str
    target_resource: str
    intent_summary: str
    payload: Dict[str, Any]
    commissioned_goal: Optional[str] = Field(
        default=None,
        description="The agent's sanctioned mandate goal. The evaluator scores "
                    "whether the action serves this goal (goal-hijacking detection).",
    )


class EvaluationResult(BaseModel):
    """The final decision from the 3-tier evaluation pipeline."""
    is_allowed: bool
    risk_score: float = Field(..., ge=0.0, le=1.0, description="0.0 is completely safe, 1.0 is definitely malicious.")
    reason: str
    evaluated_by: str = Field(..., description="Which tier made the final decision (e.g., 'RuleFilter', 'SemanticEvaluator').")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata (e.g., HITL request ID)")
    # Tier 2 evidence. Redaction happens before the payload reaches any model,
    # so without reporting it the operator has no way to confirm it occurred —
    # a privacy control nobody can observe is a privacy control nobody can trust.
    pii_redacted_count: int = Field(
        default=0, description="Number of PII values replaced before Tier-3 evaluation.")
    pii_entity_types: List[str] = Field(
        default_factory=list,
        description="Distinct PII entity types redacted, e.g. ['EMAIL_ADDRESS'].")

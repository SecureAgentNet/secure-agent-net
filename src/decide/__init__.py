from .models import EvaluationRequest, EvaluationResult
from .rule_filter import RuleFilter
from .pii_redactor import PiiRedactor
from .semantic_evaluator import SemanticEvaluator

class DecisionGateway:
    """
    The main entry point for the Decide Phase.
    Runs the 3-Tier evaluation pipeline.
    """
    
    def __init__(self):
        self.semantic_evaluator = SemanticEvaluator()
        # threshold above which we block (e.g., 70% risk)
        self.BLOCK_THRESHOLD = 0.7 
        
    def evaluate_request(self, request: EvaluationRequest) -> EvaluationResult:
        
        # Tier 1: Fast Rule Filtering
        is_blocked, rule_score, rule_reason = RuleFilter.evaluate(request)
        if is_blocked:
            return EvaluationResult(
                is_allowed=False,
                risk_score=rule_score,
                reason=rule_reason,
                evaluated_by="RuleFilter"
            )
            
        # Tier 2: PII Redaction
        redacted_payload = PiiRedactor.redact_payload(request.payload)
        
        # Tier 3: Semantic Evaluation (LLM)
        llm_score, llm_reason = self.semantic_evaluator.evaluate(request, redacted_payload)
        
        if llm_score >= self.BLOCK_THRESHOLD:
            return EvaluationResult(
                is_allowed=False,
                risk_score=llm_score,
                reason=llm_reason,
                evaluated_by="SemanticEvaluator"
            )
            
        # If it passes everything, it is allowed
        return EvaluationResult(
            is_allowed=True,
            risk_score=llm_score,
            reason="Approved by Semantic Evaluator",
            evaluated_by="SemanticEvaluator"
        )

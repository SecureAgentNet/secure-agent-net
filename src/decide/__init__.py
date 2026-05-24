import logging
import time
import uuid
from datetime import datetime, timezone

from .models import EvaluationRequest, EvaluationResult
from .rule_filter import RuleFilter
from .pii_redactor import PiiRedactor
from .semantic_evaluator import SemanticEvaluator
from src.core.config import get_settings
from src.core.exceptions import PIIRedactionError

logger = logging.getLogger(__name__)


class DecisionGateway:
    def __init__(self):
        settings = get_settings()
        self.semantic_evaluator = SemanticEvaluator()
        self.block_threshold = settings.block_threshold

    def evaluate_request(self, request: EvaluationRequest) -> EvaluationResult:
        t_start = time.time()
        tier1_result = None
        tier2_pii_count = 0
        tier2_entities = []
        tier3_confidence = None
        decision_log = {
            "decision_id": str(uuid.uuid4()),
            "agent_id": request.agent_id,
            "session_id": str(uuid.uuid4()),
            "request_hash": None,
            "tier1_result": None,
            "tier2_pii_count": 0,
            "tier2_entities": [],
            "tier3_confidence": None,
            "final_decision": None,
            "timestamp": datetime.now(timezone.utc),
            "processing_time_ms": 0,
        }

        # Tier 1: Fast Rule Filtering
        is_blocked, rule_score, rule_reason = RuleFilter.evaluate(request)
        decision_log["tier1_result"] = "blocked" if is_blocked else "passed"
        if is_blocked:
            decision_log["final_decision"] = "deny"
            result = EvaluationResult(
                is_allowed=False, risk_score=rule_score,
                reason=rule_reason, evaluated_by="RuleFilter",
            )
            self._persist_decision(decision_log, result, t_start)
            return result

        # Tier 2: PII Redaction
        try:
            redacted_payload = PiiRedactor.redact_payload(request.payload)
            decision_log["tier2_pii_count"] = self._count_redacted(
                redacted_payload, request.payload
            )
        except PIIRedactionError as e:
            logger.error("Tier 2 PII redaction failed — failing closed: %s", e)
            decision_log["final_decision"] = "deny"
            result = EvaluationResult(
                is_allowed=False, risk_score=1.0,
                reason=f"PII redaction unavailable: {e}",
                evaluated_by="PiiRedactor (fail-closed)",
            )
            self._persist_decision(decision_log, result, t_start)
            return result

        # Tier 3: Semantic Evaluation (LLM)
        llm_score, llm_reason = self.semantic_evaluator.evaluate(
            request, redacted_payload
        )
        decision_log["tier3_confidence"] = llm_score

        if llm_score >= self.block_threshold:
            decision_log["final_decision"] = "deny"
            result = EvaluationResult(
                is_allowed=False, risk_score=llm_score,
                reason=llm_reason, evaluated_by="SemanticEvaluator",
            )
        else:
            decision_log["final_decision"] = "approve"
            result = EvaluationResult(
                is_allowed=True, risk_score=llm_score,
                reason="Approved by Semantic Evaluator",
                evaluated_by="SemanticEvaluator",
            )

        self._persist_decision(decision_log, result, t_start)
        return result

    @staticmethod
    def _count_redacted(redacted: dict, original: dict) -> int:
        redacted_str = str(redacted)
        return redacted_str.count("[REDACTED_")

    def _persist_decision(self, log: dict, result: EvaluationResult, t_start: float):
        log["processing_time_ms"] = int((time.time() - t_start) * 1000)
        log["final_decision"] = "approve" if result.is_allowed else "deny"
        try:
            from src.database.connection import get_db_session
            from src.database.models import DecisionLog as DecisionLogModel
            with get_db_session() as session:
                dl = DecisionLogModel(
                    agent_id=log.get("agent_id"),
                    session_id=log.get("session_id"),
                    request_hash=log.get("request_hash"),
                    tier1_result=log.get("tier1_result"),
                    tier2_pii_count=log.get("tier2_pii_count", 0),
                    tier2_entities=log.get("tier2_entities"),
                    tier3_confidence=log.get("tier3_confidence"),
                    final_decision=log.get("final_decision"),
                    timestamp=log.get("timestamp"),
                    processing_time_ms=log.get("processing_time_ms", 0),
                )
                session.add(dl)
        except Exception as e:
            logger.warning("Failed to persist decision log: %s", e)
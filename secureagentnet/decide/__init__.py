import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import EvaluationRequest, EvaluationResult
from .rule_filter import RuleFilter
from .pii_redactor import PiiRedactor
from .semantic_evaluator import SemanticEvaluator
from .hitl import get_hitl_gate, HITLDecision
from .ast_verifier import ASTSemanticVerifier
from secureagentnet.core.config import get_settings
from secureagentnet.core.exceptions import PIIRedactionError
from secureagentnet.integrations.cloud_scanner import CloudScanner

logger = logging.getLogger(__name__)


class DecisionGateway:
    def __init__(self):
        settings = get_settings()
        self.semantic_evaluator = SemanticEvaluator()
        self.block_threshold = settings.block_threshold
        self.cloud_scanner = CloudScanner()
        self.host_telemetry_enabled = getattr(
            settings, "decide_host_telemetry_enabled", False)

    def evaluate_request(self, request: EvaluationRequest) -> EvaluationResult:
        t_start = time.time()
        tier1_result = None
        tier2_pii_count = 0
        tier2_entities: List[Any] = []
        tier3_confidence = None
        decision_log: Dict[str, Any] = {
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
        decision_log["tier1_result"] = "DENY" if is_blocked else "PASS"

        # Tier 1.5: AST Semantic Drift Verification (code execution only)
        if not is_blocked and request.action_name in ("execute_code", "execute", "run"):
            code = request.payload.get("code") or request.payload.get("command") or ""
            if code:
                from secureagentnet.identify.identity_registry import IdentityRegistry
                agent = IdentityRegistry.get_agent(request.agent_id)
                caps = list(agent.get("capabilities", {}).keys()) if agent else []
                ast_safe, ast_risk, ast_reason = ASTSemanticVerifier.verify(
                    code=code,
                    declared_intent=request.intent_summary,
                    allowed_capabilities=caps,
                )
                if not ast_safe:
                    decision_log["final_decision"] = "DENY"
                    decision_log["tier1_result"] = "DENY"
                    result = EvaluationResult(
                        is_allowed=False, risk_score=ast_risk,
                        reason=f"AST verification: {ast_reason}",
                        evaluated_by="ASTSemanticVerifier",
                    )
                    self._persist_decision(decision_log, result, t_start)
                    return result

        if is_blocked:
            decision_log["final_decision"] = "DENY"
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
            decision_log["final_decision"] = "DENY"
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

        # Tier 4: Optional Cloud Scan (remote + fallback)
        cloud_result = self.cloud_scanner.scan(
            agent_id=request.agent_id,
            action_name=request.action_name,
            payload=dict(redacted_payload),
            intent=request.intent_summary,
        )
        # Use the higher of the two risk scores.
        final_score = max(llm_score, cloud_result.risk_score)
        final_reason = cloud_result.reason if cloud_result.risk_score > llm_score else llm_reason
        final_source = f"SemanticEvaluator+{cloud_result.source}"

        # Tier 3.2: Host-telemetry context. A live host anomaly (e.g. an
        # outbound-network spike) during an exfiltration-shaped action raises the
        # risk toward the HITL band. Additive only — it never lowers the score or
        # denies on its own. Opt-in via DECIDE_HOST_TELEMETRY.
        if self.host_telemetry_enabled:
            from secureagentnet.monitoring.host_telemetry import get_host_telemetry_monitor
            host_ctx = get_host_telemetry_monitor().assess(
                request.action_name, request.target_resource or "",
                request.intent_summary or "")
            decision_log["host_context"] = host_ctx.to_dict()
            if host_ctx.risk > final_score:
                final_score = host_ctx.risk
                final_reason = host_ctx.reason
                final_source = f"{final_source}+HostTelemetry"

        # Tier 3.5: HITL Approval Gate for medium-risk actions
        hitl = get_hitl_gate()
        if hitl.requires_approval(final_score) and final_score < self.block_threshold:
            hitl_id = hitl.create_pending_request(
                request_id=str(uuid.uuid4()),
                agent_id=request.agent_id,
                action_name=request.action_name,
                target_resource=request.target_resource,
                intent_summary=request.intent_summary,
                risk_score=final_score,
                reason=final_reason,
            )
            decision_log["final_decision"] = "ESCALATE"
            decision_log["hitl_request_id"] = hitl_id
            decision_log["tier3_confidence"] = final_score
            result = EvaluationResult(
                is_allowed=False,
                risk_score=final_score,
                reason=f"HITL approval required for: {request.action_name} ({final_reason})",
                evaluated_by="HITLApprovalGate",
                metadata={"hitl_request_id": hitl_id, "hitl_required": True, "cloud_scan": cloud_result.to_dict()},
            )
            self._persist_decision(decision_log, result, t_start)
            return result

        if final_score >= self.block_threshold:
            decision_log["final_decision"] = "DENY"
            result = EvaluationResult(
                is_allowed=False, risk_score=final_score,
                reason=final_reason, evaluated_by=final_source,
                metadata={"cloud_scan": cloud_result.to_dict()},
            )
        else:
            decision_log["final_decision"] = "APPROVE"
            result = EvaluationResult(
                is_allowed=True, risk_score=final_score,
                reason="Approved by Semantic Evaluator",
                evaluated_by=final_source,
                metadata={"cloud_scan": cloud_result.to_dict()},
            )

        self._persist_decision(decision_log, result, t_start)
        return result

    @staticmethod
    def _count_redacted(redacted: dict, original: dict) -> int:
        redacted_str = str(redacted)
        return redacted_str.count("[REDACTED_")

    def _persist_decision(self, log: dict, result: EvaluationResult, t_start: float):
        log["processing_time_ms"] = int((time.time() - t_start) * 1000)
        log["final_decision"] = "APPROVE" if result.is_allowed else "DENY"
        try:
            from secureagentnet.database.connection import get_db_session
            from secureagentnet.database.models import DecisionLog as DecisionLogModel
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
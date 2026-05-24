import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from src.core.constants import PipelinePhase, EventSeverity
from src.core.config import get_settings
from src.core.exceptions import PipelineBlockedError, IntentCapsuleExpiredError
from src.track.models import AgentActionRequest
from src.track.structured_logger import AgentAuditor, StructuredLogger
from src.track.log_indexer import LogIndexer
from src.track.reasoning_capture import ReasoningCaptureMiddleware
from src.decide import DecisionGateway
from src.decide.models import EvaluationRequest
from src.decide.circuit_breaker import CircuitBreaker
from src.decide.kill_switch import KillSwitchController
from src.decide.intent_capsule import IntentCapsule
from src.contain.container_provisioner import ContainerProvisioner
from src.contain.models import ExecutionRequest, SandboxConfig
from src.contain.resource_manager import ContainerResourceManager
from src.identify.identity_registry import IdentityRegistry
from src.identify.capability_profiler import CapabilityProfiler
from src.identify.rogue_detector import RogueDetector
from src.utils.helpers import generate_correlation_id, calculate_execution_time_ms
from src.utils.validators import sanitize_command

logger = logging.getLogger("SecureAgentNet.Pipeline")


class ITCDPipeline:
    def __init__(self):
        self.gateway = DecisionGateway()
        self.provisioner = ContainerProvisioner()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=3, time_window_seconds=60, reset_timeout_seconds=120
        )
        self.kill_switch = KillSwitchController()
        self.rogue_detector = RogueDetector()
        self.auditor = AgentAuditor()
        self.logger = StructuredLogger()
        self._initialized = True
        logger.info("ITCD Pipeline initialized. Phase order: IDENTIFY → TRACK → DECIDE → CONTAIN")

    def _log_event(
        self,
        agent_id: str,
        event_type: str,
        phase: PipelinePhase,
        severity: EventSeverity = EventSeverity.INFO,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "event_type": event_type,
            "phase": phase.value,
            "severity": severity.value,
            "details": details or {},
            "correlation_id": correlation_id or "",
        }
        LogIndexer.index_event(event)
        self.logger.log(severity.value, f"[{phase.value}] {agent_id}: {event_type}")

    async def execute_agent_action(
        self,
        agent_id: str,
        request: AgentActionRequest,
        command: str,
        session_id: Optional[str] = None,
        intent_capsule: Optional[IntentCapsule] = None,
    ) -> Dict[str, Any]:
        correlation_id = generate_correlation_id()
        start_time = time.time()
        self.rogue_detector.record_request(agent_id, request.action_name, request.target_resource)
        self._log_event(agent_id, "pipeline_started", PipelinePhase.IDENTIFY, correlation_id=correlation_id)

        # === IDENTIFY PHASE ===
        is_suspicious, score, reason = self.rogue_detector.is_suspicious(agent_id)
        if is_suspicious:
            self._log_event(agent_id, "rogue_detected", PipelinePhase.IDENTIFY, EventSeverity.WARNING, {"anomaly_score": score, "reason": reason}, correlation_id)
            IdentityRegistry.update_trust_score(agent_id, -10)
            IdentityRegistry.mark_rogue(agent_id)
            return {"status": "blocked", "reason": f"Rogue agent detected: {reason}", "evaluated_by": "RogueDetector", "phase": "IDENTIFY"}

        try:
            self.kill_switch.check()
        except Exception as e:
            self._log_event(agent_id, "kill_switch_blocked", PipelinePhase.IDENTIFY, EventSeverity.CRITICAL, correlation_id=correlation_id)
            return {"status": "blocked", "reason": str(e), "evaluated_by": "KillSwitch", "phase": "IDENTIFY"}

        cb_allowed, cb_reason = self.circuit_breaker.check_access(agent_id)
        if not cb_allowed:
            self._log_event(agent_id, "circuit_breaker_blocked", PipelinePhase.IDENTIFY, EventSeverity.WARNING, {"reason": cb_reason}, correlation_id)
            return {"status": "blocked", "reason": cb_reason, "evaluated_by": "CircuitBreaker", "phase": "IDENTIFY"}

        try:
            IdentityRegistry.check_agent_active(agent_id)
        except Exception as e:
            self._log_event(agent_id, "agent_inactive", PipelinePhase.IDENTIFY, EventSeverity.WARNING, correlation_id=correlation_id)
            return {"status": "blocked", "reason": str(e), "evaluated_by": "IdentityRegistry", "phase": "IDENTIFY"}

        if not CapabilityProfiler.is_authorized(agent_id, request.action_name):
            reason = f"Agent lacks capability: {request.action_name}"
            self.circuit_breaker.record_failure(agent_id)
            self._log_event(agent_id, "capability_denied", PipelinePhase.IDENTIFY, EventSeverity.WARNING, {"action": request.action_name}, correlation_id)
            IdentityRegistry.update_trust_score(agent_id, -5)
            return {"status": "blocked", "reason": reason, "evaluated_by": "CapabilityProfiler", "phase": "IDENTIFY"}

        if intent_capsule is not None:
            if intent_capsule.is_expired():
                raise IntentCapsuleExpiredError(
                    f"Session {intent_capsule.session_id} has expired"
                )
            hijack = intent_capsule.detect_goal_hijack(
                request.action_name, request.intent_summary
            )
            if hijack:
                IdentityRegistry.update_trust_score(agent_id, -20)
                self.rogue_detector.record_failure(agent_id)
                self.kill_switch.record_denial(agent_id)
                self._log_event(agent_id, "goal_hijack_detected", PipelinePhase.IDENTIFY,
                                EventSeverity.CRITICAL, {"action": request.action_name}, correlation_id)
                return {"status": "blocked",
                        "reason": f"Goal hijacking detected: action '{request.action_name}' deviates from capsule intent",
                        "evaluated_by": "IntentCapsule", "phase": "IDENTIFY"}

            if not intent_capsule.is_action_allowed(request.action_name):
                self._log_event(agent_id, "action_forbidden_by_capsule", PipelinePhase.IDENTIFY,
                                EventSeverity.WARNING, {"action": request.action_name}, correlation_id)
                return {"status": "blocked",
                        "reason": f"Action '{request.action_name}' is forbidden by session capsule",
                        "evaluated_by": "IntentCapsule", "phase": "IDENTIFY"}

        IdentityRegistry.update_trust_score(agent_id, 1)
        self._log_event(agent_id, "identify_passed", PipelinePhase.IDENTIFY, correlation_id=correlation_id)

        # === TRACK (intent capture) + DECIDE + CONTAIN ===

        async def decide_and_contain():
            eval_req = EvaluationRequest(
                agent_id=agent_id,
                action_name=request.action_name,
                target_resource=request.target_resource,
                intent_summary=request.intent_summary,
                payload=request.payload,
            )
            decision = self.gateway.evaluate_request(eval_req)
            self._log_event(
                agent_id,
                f"decision_{'approved' if decision.is_allowed else 'denied'}",
                PipelinePhase.DECIDE,
                EventSeverity.INFO if decision.is_allowed else EventSeverity.WARNING,
                {"risk_score": decision.risk_score, "evaluated_by": decision.evaluated_by, "reason": decision.reason},
                correlation_id,
            )
            if not decision.is_allowed:
                raise PipelineBlockedError(
                    reason=decision.reason,
                    evaluated_by=decision.evaluated_by,
                    risk_score=decision.risk_score,
                )

            safe_command = sanitize_command(command)
            exec_req = ExecutionRequest(
                command=safe_command,
                environment_vars={"AGENT_ID": agent_id, "CORRELATION_ID": correlation_id},
            )
            sandbox_config = SandboxConfig(
                timeout_seconds=get_settings().container_timeout_seconds,
            )
            return self.provisioner.run_in_sandbox(exec_req, sandbox_config)

        result = await ReasoningCaptureMiddleware.capture_and_evaluate(
            agent_id=agent_id,
            request=request,
            execute_callback=decide_and_contain,
        )

        if result["status"] == "blocked":
            self.circuit_breaker.record_failure(agent_id)
            IdentityRegistry.update_trust_score(agent_id, -10)
            self.rogue_detector.record_failure(agent_id)
            self.kill_switch.record_denial(agent_id)
            return {
                "status": "blocked",
                "risk_score": result.get("risk_score", 1.0),
                "reason": result["reason"],
                "evaluated_by": result.get("evaluated_by", "DECIDE"),
                "phase": "DECIDE",
                "vault_receipt": result.get("vault_receipt"),
                "correlation_id": correlation_id,
            }

        if result["status"] == "error":
            self._log_event(agent_id, "container_failed", PipelinePhase.CONTAIN, EventSeverity.ERROR,
                            {"error": result.get("error_details", "")}, correlation_id)
            return {
                "status": "error",
                "error_details": result.get("error_details", "Unknown error"),
                "correlation_id": correlation_id,
            }

        # Success
        exec_data = result["data"]
        total_time = calculate_execution_time_ms(start_time)

        IdentityRegistry.update_trust_score(agent_id, 2)
        self._log_event(
            agent_id,
            "pipeline_completed",
            PipelinePhase.CONTAIN,
            details={
                "vault_receipt": result["vault_receipt"],
                "total_time_ms": total_time,
                "exit_code": getattr(exec_data, "exit_code", None),
            },
            correlation_id=correlation_id,
        )

        return {
            "status": "success",
            "vault_receipt": result["vault_receipt"],
            "data": exec_data.model_dump() if hasattr(exec_data, "model_dump") else exec_data,
            "correlation_id": correlation_id,
        }

    def get_pipeline_status(self) -> Dict[str, Any]:
        return {
            "kill_switch": self.kill_switch.get_status(),
            "circuit_breaker": {"agents_tracked": len(self.circuit_breaker._state_store)},
            "rogue_detector": {"agents_tracked": len(self.rogue_detector._profiles)},
            "containers": ContainerResourceManager.get_resource_usage_summary(),
            "agents": {"active": IdentityRegistry.get_active_count(), "total": IdentityRegistry.get_total_count()},
        }

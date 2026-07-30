import asyncio
import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from secureagentnet.core.constants import PipelinePhase, EventSeverity
from secureagentnet.core.config import get_settings
from secureagentnet.core.exceptions import PipelineBlockedError, IntentCapsuleExpiredError
from secureagentnet.track.models import AgentActionRequest
from secureagentnet.track.structured_logger import AgentAuditor, StructuredLogger
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.track.reasoning_capture import ReasoningCaptureMiddleware
from secureagentnet.decide import DecisionGateway
from secureagentnet.decide.models import EvaluationRequest
from secureagentnet.decide.circuit_breaker import CircuitBreaker
from secureagentnet.decide.kill_switch import KillSwitchController
from secureagentnet.decide.intent_capsule import IntentCapsule, MandateRegistry
from secureagentnet.contain.container_provisioner import ContainerProvisioner
from secureagentnet.contain.models import ExecutionRequest, SandboxConfig
from secureagentnet.contain.resource_manager import ContainerResourceManager
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.identify.capability_profiler import CapabilityProfiler
from secureagentnet.identify.rogue_detector import RogueDetector, get_rogue_detector
from secureagentnet.utils.helpers import generate_correlation_id, calculate_execution_time_ms
from secureagentnet.utils.validators import sanitize_command

logger = logging.getLogger("SecureAgentNet.Pipeline")


class ITCDPipeline:
    def __init__(self):
        self.gateway = DecisionGateway()
        self.provisioner = ContainerProvisioner()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=3, time_window_seconds=60, reset_timeout_seconds=120
        )
        self.kill_switch = KillSwitchController()
        self.rogue_detector = get_rogue_detector()
        self.auditor = AgentAuditor()
        self.logger = StructuredLogger()
        self._initialized = True
        logger.info("ITCD Pipeline initialized. Phase order: IDENTIFY → TRACK → CONTAIN → DECIDE")

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
        presented_public_key: Optional[str] = None,
        files: Optional[list] = None,
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

        # === TRUST CHAIN (Deliverable 3) ===
        # The agent's action must chain back to the SAN root authority via its signed
        # manifest. Enforced here in the shared IDENTIFY phase so EVERY entry point
        # (daemon /v1/intercept, framework adapters, MCP gateway) is covered — not just
        # the MCP route. Fail-closed on a tampered, expired, revoked or key-mismatched
        # manifest. A registered-but-unmanifested agent (e.g. persisted before the trust
        # chain existed) is backfilled once, then re-verified.
        from secureagentnet.identify.trust_chain import TrustChainService
        trusted, treason = TrustChainService.verify_agent(agent_id, presented_public_key)
        if not trusted and TrustChainService.get_manifest(agent_id) is None:
            if IdentityRegistry.ensure_manifest(agent_id):
                trusted, treason = TrustChainService.verify_agent(agent_id, presented_public_key)
        if not trusted:
            self._log_event(agent_id, "trust_chain_failed", PipelinePhase.IDENTIFY,
                            EventSeverity.WARNING, {"reason": treason}, correlation_id)
            IdentityRegistry.update_trust_score(agent_id, -10)
            return {"status": "blocked", "reason": f"Trust chain verification failed: {treason}",
                    "evaluated_by": "TrustChainService", "phase": "IDENTIFY"}

        if not CapabilityProfiler.is_authorized(agent_id, request.action_name):
            reason = f"Agent lacks capability: {request.action_name}"
            self.circuit_breaker.record_failure(agent_id)
            self._log_event(agent_id, "capability_denied", PipelinePhase.IDENTIFY, EventSeverity.WARNING, {"action": request.action_name}, correlation_id)
            IdentityRegistry.update_trust_score(agent_id, -5)
            return {"status": "blocked", "reason": reason, "evaluated_by": "CapabilityProfiler", "phase": "IDENTIFY"}

        # === MANDATE CHECK ===
        # An explicit per-call capsule wins; otherwise load the agent's durable,
        # commissioned mandate. Policy is fail-closed: no mandate = no action.
        mandate = intent_capsule or MandateRegistry.get_active(agent_id)
        if mandate is None:
            self.circuit_breaker.record_failure(agent_id)
            self._log_event(agent_id, "no_mandate", PipelinePhase.IDENTIFY,
                            EventSeverity.WARNING, {"action": request.action_name}, correlation_id)
            return {"status": "blocked",
                    "reason": "Agent has no active mandate — it has not been commissioned for any task",
                    "evaluated_by": "MandateRegistry", "phase": "IDENTIFY"}

        if mandate.is_expired():
            self._log_event(agent_id, "mandate_expired", PipelinePhase.IDENTIFY,
                            EventSeverity.WARNING, {"action": request.action_name}, correlation_id)
            return {"status": "blocked",
                    "reason": f"Agent mandate {mandate.session_id} has expired — re-commission required",
                    "evaluated_by": "MandateRegistry", "phase": "IDENTIFY"}

        if mandate.detect_goal_hijack(request.action_name, request.intent_summary):
            IdentityRegistry.update_trust_score(agent_id, -20)
            self.rogue_detector.record_failure(agent_id)
            self.kill_switch.record_denial(agent_id)
            self._log_event(agent_id, "goal_hijack_detected", PipelinePhase.IDENTIFY,
                            EventSeverity.CRITICAL, {"action": request.action_name}, correlation_id)
            return {"status": "blocked",
                    "reason": f"Goal hijacking detected: action '{request.action_name}' deviates from commissioned mandate",
                    "evaluated_by": "MandateRegistry", "phase": "IDENTIFY"}

        if not mandate.is_action_allowed(request.action_name):
            self._log_event(agent_id, "action_outside_mandate", PipelinePhase.IDENTIFY,
                            EventSeverity.WARNING, {"action": request.action_name}, correlation_id)
            return {"status": "blocked",
                    "reason": f"Action '{request.action_name}' is outside the agent's commissioned mandate",
                    "evaluated_by": "MandateRegistry", "phase": "IDENTIFY"}

        IdentityRegistry.update_trust_score(agent_id, 1)
        self._log_event(agent_id, "identify_passed", PipelinePhase.IDENTIFY, correlation_id=correlation_id)

        # === TRACK (intent capture) wraps CONTAIN → DECIDE → execute ===

        async def contain_decide_execute():
            # --- CONTAIN PHASE: provision the isolated sandbox up-front ---
            safe_command = sanitize_command(command)
            exec_req = ExecutionRequest(
                command=safe_command,
                environment_vars={"AGENT_ID": agent_id, "CORRELATION_ID": correlation_id},
                files=files or [],
            )
            sandbox_config = SandboxConfig(
                timeout_seconds=get_settings().container_timeout_seconds,
            )
            handle = self.provisioner.provision_sandbox(exec_req, sandbox_config)
            self._log_event(
                agent_id,
                "container_provisioned",
                PipelinePhase.CONTAIN,
                EventSeverity.INFO,
                {"sandbox_id": handle.sandbox_id, "command": safe_command},
                correlation_id,
            )

            # --- DECIDE PHASE: evaluate the request inside the containment ---
            try:
                eval_req = EvaluationRequest(
                    agent_id=agent_id,
                    action_name=request.action_name,
                    target_resource=request.target_resource,
                    intent_summary=request.intent_summary,
                    payload=request.payload,
                    commissioned_goal=mandate.original_goal,
                )
                # Tier 3 makes a blocking multi-second LLM call; run it in a
                # worker thread so it doesn't stall the event loop for every
                # other in-flight request.
                decision = await asyncio.to_thread(self.gateway.evaluate_request, eval_req)
            except Exception:
                # Any DECIDE failure — destroy the provisioned container unexecuted.
                self.provisioner.teardown_sandbox(handle, executed=False)
                raise

            self._log_event(
                agent_id,
                f"decision_{'approved' if decision.is_allowed else 'denied'}",
                PipelinePhase.DECIDE,
                EventSeverity.INFO if decision.is_allowed else EventSeverity.WARNING,
                {"risk_score": decision.risk_score, "evaluated_by": decision.evaluated_by, "reason": decision.reason},
                correlation_id,
            )

            if not decision.is_allowed:
                # Denied (or escalated to HITL) — kill the container without running it.
                self.provisioner.teardown_sandbox(handle, executed=False)
                self._log_event(
                    agent_id,
                    "container_killed_unexecuted",
                    PipelinePhase.CONTAIN,
                    EventSeverity.WARNING,
                    {"sandbox_id": handle.sandbox_id, "evaluated_by": decision.evaluated_by},
                    correlation_id,
                )
                metadata = getattr(decision, "metadata", {}) or {}
                raise PipelineBlockedError(
                    reason=decision.reason,
                    evaluated_by=decision.evaluated_by,
                    risk_score=decision.risk_score,
                    metadata=metadata,
                )

            # --- Approved: execute the workload within the contained sandbox ---
            self._log_event(
                agent_id,
                "container_executed",
                PipelinePhase.CONTAIN,
                EventSeverity.INFO,
                {"command": safe_command, "sandbox_id": handle.sandbox_id},
                correlation_id,
            )
            try:
                return self.provisioner.execute_in_sandbox(handle)
            finally:
                self.provisioner.teardown_sandbox(handle)

        result = await ReasoningCaptureMiddleware.capture_and_evaluate(
            agent_id=agent_id,
            request=request,
            execute_callback=contain_decide_execute,
        )

        if result["status"] == "blocked":
            is_hitl = result.get("metadata", {}).get("hitl_required", False)
            if not is_hitl:
                self.circuit_breaker.record_failure(agent_id)
                IdentityRegistry.update_trust_score(agent_id, -10)
                self.rogue_detector.record_failure(agent_id)
                self.kill_switch.record_denial(agent_id)
            return {
                "status": "escalated" if is_hitl else "blocked",
                "risk_score": result.get("risk_score", 1.0),
                "reason": result["reason"],
                "evaluated_by": result.get("evaluated_by", "DECIDE"),
                "phase": "DECIDE",
                "vault_receipt": result.get("vault_receipt"),
                "correlation_id": correlation_id,
                "metadata": result.get("metadata", {}),
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

        # Per-agent resource attribution: the sandbox that just ran belongs to
        # exactly this agent, so its container counters name who egressed data or
        # burned resources. Anomalies raise the agent's rogue-detection score and
        # dock trust — connecting CONTAIN telemetry to IDENTIFY rogue detection.
        resource_usage = getattr(exec_data, "resource_usage", None)
        oom_killed = bool(getattr(exec_data, "oom_killed", False))
        if resource_usage or oom_killed:
            flagged, why = self.rogue_detector.record_resource_usage(
                agent_id, resource_usage or {}, oom_killed=oom_killed)
            if flagged:
                self._log_event(agent_id, "resource_anomaly", PipelinePhase.CONTAIN,
                                EventSeverity.WARNING, {"detail": why}, correlation_id)
                IdentityRegistry.update_trust_score(agent_id, -8)

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

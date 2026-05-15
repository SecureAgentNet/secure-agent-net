import asyncio
import logging
from typing import Dict, Any

from src.track.models import AgentActionRequest
from src.track.reasoning_capture import ReasoningCaptureMiddleware
from src.decide import DecisionGateway
from src.decide.models import EvaluationRequest
from src.decide.circuit_breaker import CircuitBreaker
from src.contain.container_provisioner import ContainerProvisioner
from src.contain.models import ExecutionRequest
from src.identify.capability_profiler import CapabilityProfiler

logger = logging.getLogger("SecureAgentNet.Pipeline")

class ITCDPipeline:
    """
    The orchestrator that ties together all 4 phases:
    Identify, Track, Decide, and Contain.
    """
    def __init__(self):
        self.gateway = DecisionGateway()
        self.provisioner = ContainerProvisioner()
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, time_window_seconds=60)
        
    async def execute_agent_action(self, agent_id: str, request: AgentActionRequest, command: str) -> Dict[str, Any]:
        """
        Runs the full Zero-Trust pipeline for a single agent action.
        """
        logger.info(f"Pipeline triggered for Agent {agent_id}, Action: {request.action_name}")
        
        # 1. IDENTIFY Phase (Pre-check)
        # Check Circuit Breaker
        cb_allowed, cb_reason = self.circuit_breaker.check_access(agent_id)
        if not cb_allowed:
            logger.warning(cb_reason)
            return {"status": "blocked", "reason": cb_reason, "evaluated_by": "CircuitBreaker"}
            
        # Check Capability Profiler (Least Privilege)
        if not CapabilityProfiler.is_authorized(agent_id, request.action_name):
            reason = f"Agent does not have the required capability: {request.action_name}"
            self.circuit_breaker.record_failure(agent_id) # Unauthorized access counts as a failure
            return {"status": "blocked", "reason": reason, "evaluated_by": "CapabilityProfiler"}
        
        # 2. Prepare the evaluation request for the Decide phase
        eval_req = EvaluationRequest(
            agent_id=agent_id,
            action_name=request.action_name,
            target_resource=request.target_resource,
            intent_summary=request.intent_summary,
            payload=request.payload
        )
        
        # 3. DECIDE Phase
        decision = self.gateway.evaluate_request(eval_req)
        
        if not decision.is_allowed:
            logger.warning(f"BLOCKED by {decision.evaluated_by}. Score: {decision.risk_score}. Reason: {decision.reason}")
            
            # Record the failure to trip the circuit breaker if they keep doing this
            self.circuit_breaker.record_failure(agent_id)
            
            return {
                "status": "blocked",
                "risk_score": decision.risk_score,
                "reason": decision.reason,
                "evaluated_by": decision.evaluated_by
            }
            
        logger.info(f"APPROVED by {decision.evaluated_by}. Score: {decision.risk_score}.")
        
        # 4. CONTAIN Phase Preparation
        exec_req = ExecutionRequest(
            command=command,
            environment_vars={"AGENT_ID": agent_id}
        )
        
        # Define the execution callback that actually runs the sandbox
        async def run_sandbox():
            return self.provisioner.run_in_sandbox(exec_req).model_dump()
            
        # 5. TRACK Phase (Middleware wraps execution)
        result = await ReasoningCaptureMiddleware.capture_and_evaluate(
            agent_id=agent_id,
            request=request,
            execute_callback=run_sandbox
        )
        
        return result

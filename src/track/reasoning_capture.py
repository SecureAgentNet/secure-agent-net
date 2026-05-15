from typing import Any, Callable, Dict
from src.track.models import AgentActionRequest, CapturedLog
from src.track.structured_logger import AgentAuditor

auditor = AgentAuditor()

class ReasoningCaptureMiddleware:
    """
    Middleware pattern to wrap the execution of an agent's requested action.
    This ensures that NO action is taken without first logging the intent.
    """
    
    @staticmethod
    async def capture_and_evaluate(
        agent_id: str, 
        request: AgentActionRequest, 
        execute_callback: Callable, 
        *args, **kwargs
    ) -> Dict[str, Any]:
        """
        Intercepts the request, logs the intent, triggers the execution callback 
        if safe, and updates the log with the result.
        
        :param agent_id: The ID of the agent making the request (from JWT).
        :param request: The AgentActionRequest containing intent and payload.
        :param execute_callback: The function to call to actually perform the action.
        """
        
        # 1. Create the initial log event (Pre-execution)
        log_event = CapturedLog(
            agent_id=agent_id,
            action_request=request,
            decision="pending"
        )
        
        # Log to Vault BEFORE execution (Intent capture)
        log_event = auditor.capture(log_event)
        
        # 2. Execution (In the real pipeline, this callback calls the Decide & Contain phases)
        try:
            # Execute the actual tool
            result = await execute_callback(*args, **kwargs)
            
            # 3. Post-execution update (Success)
            log_event.decision = "allowed"
            # We would typically update the DB here with the execution_time_ms
            
            return {
                "status": "success",
                "vault_receipt": log_event.vault_receipt_id,
                "data": result
            }
            
        except Exception as e:
            # 3. Post-execution update (Failure or Blocked)
            log_event.decision = "blocked_or_failed"
            # We would log the error to the DB here
            
            return {
                "status": "error",
                "vault_receipt": log_event.vault_receipt_id,
                "error_details": str(e)
            }

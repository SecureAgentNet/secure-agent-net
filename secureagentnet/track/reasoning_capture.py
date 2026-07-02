from typing import Any, Callable, Dict
from secureagentnet.track.models import AgentActionRequest, CapturedLog
from secureagentnet.track.structured_logger import AgentAuditor
from secureagentnet.core.exceptions import PipelineBlockedError

auditor = AgentAuditor()


class ReasoningCaptureMiddleware:
    @staticmethod
    async def capture_and_evaluate(
        agent_id: str,
        request: AgentActionRequest,
        execute_callback: Callable,
        *args, **kwargs
    ) -> Dict[str, Any]:
        log_event = CapturedLog(
            agent_id=agent_id,
            action_request=request,
            decision="pending",
        )
        log_event = auditor.capture(log_event)

        try:
            result = await execute_callback(*args, **kwargs)
            log_event.decision = "allowed"
            return {
                "status": "success",
                "vault_receipt": log_event.vault_receipt_id,
                "data": result,
            }
        except PipelineBlockedError as blocked:
            log_event.decision = "blocked"
            result = {
                "status": "blocked",
                "vault_receipt": log_event.vault_receipt_id,
                "reason": blocked.reason,
                "risk_score": blocked.risk_score,
                "evaluated_by": blocked.evaluated_by,
            }
            if getattr(blocked, "metadata", None):
                result["metadata"] = blocked.metadata
            return result
        except Exception as e:
            log_event.decision = "failed"
            return {
                "status": "error",
                "vault_receipt": log_event.vault_receipt_id,
                "error_details": str(e),
            }

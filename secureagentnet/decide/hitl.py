import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)

HITL_TIMEOUT_SECONDS = 60


class HITLDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    PENDING = "pending"


class HITLApprovalGate:
    """Human-in-the-Loop approval system for moderate-risk agent actions.

    When an action's risk score falls in the medium range (0.4 - 0.7),
    the pipeline pauses execution and requests operator approval.
    """

    def __init__(self):
        self._pending_requests: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._callbacks: Dict[str, Callable] = {}

    @property
    def pending_count(self) -> int:
        return len(self._pending_requests)

    def requires_approval(self, risk_score: float) -> bool:
        settings = None
        try:
            from secureagentnet.core.config import get_settings
            settings = get_settings()
        except Exception:
            pass
        low = getattr(settings, 'hitl_low_threshold', 0.3) if settings else 0.3
        high = getattr(settings, 'hitl_high_threshold', 0.7) if settings else 0.7
        return low <= risk_score < high

    def create_pending_request(
        self,
        request_id: str,
        agent_id: str,
        action_name: str,
        target_resource: str,
        intent_summary: str,
        risk_score: float,
        reason: str,
    ) -> str:
        req = {
            "request_id": request_id,
            "agent_id": agent_id,
            "action_name": action_name,
            "target_resource": target_resource,
            "intent_summary": intent_summary,
            "risk_score": risk_score,
            "reason": reason,
            "status": HITLDecision.PENDING.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "decision_at": None,
            "decided_by": None,
        }
        with self._lock:
            self._pending_requests[request_id] = req
        logger.info(
            "HITL: action '%s' by agent %s queued for approval (risk=%.2f)",
            action_name, agent_id, risk_score,
        )
        return request_id

    def approve(self, request_id: str, operator: str = "cli") -> HITLDecision:
        with self._lock:
            req = self._pending_requests.get(request_id)
            if not req:
                return HITLDecision.TIMED_OUT
            if req["status"] != HITLDecision.PENDING.value:
                return HITLDecision(req["status"])
            req["status"] = HITLDecision.APPROVED.value
            req["decision_at"] = datetime.now(timezone.utc).isoformat()
            req["decided_by"] = operator
        logger.info("HITL: request %s APPROVED by %s", request_id, operator)
        self._invoke_callback(request_id, HITLDecision.APPROVED)
        return HITLDecision.APPROVED

    def deny(self, request_id: str, operator: str = "cli") -> HITLDecision:
        with self._lock:
            req = self._pending_requests.get(request_id)
            if not req:
                return HITLDecision.TIMED_OUT
            if req["status"] != HITLDecision.PENDING.value:
                return HITLDecision(req["status"])
            req["status"] = HITLDecision.DENIED.value
            req["decision_at"] = datetime.now(timezone.utc).isoformat()
            req["decided_by"] = operator
        logger.info("HITL: request %s DENIED by %s", request_id, operator)
        self._invoke_callback(request_id, HITLDecision.DENIED)
        return HITLDecision.DENIED

    def wait_for_decision(self, request_id: str, timeout: int = HITL_TIMEOUT_SECONDS) -> HITLDecision:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                req = self._pending_requests.get(request_id)
                if not req:
                    return HITLDecision.TIMED_OUT
                if req["status"] != HITLDecision.PENDING.value:
                    return HITLDecision(req["status"])
            time.sleep(0.5)

        logger.warning("HITL: request %s timed out after %ds — denying", request_id, timeout)
        self.deny(request_id, "timeout")
        return HITLDecision.TIMED_OUT

    def get_pending_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._pending_requests.get(request_id)

    def get_all_pending(self) -> list:
        with self._lock:
            return [
                r for r in self._pending_requests.values()
                if r["status"] == HITLDecision.PENDING.value
            ]

    def on_decision(self, request_id: str, callback: Callable):
        self._callbacks[request_id] = callback

    def _invoke_callback(self, request_id: str, decision: HITLDecision):
        cb = self._callbacks.pop(request_id, None)
        if cb:
            try:
                cb(decision)
            except Exception as e:
                logger.error("HITL callback failed for %s: %s", request_id, e)

    def cleanup(self, request_id: str):
        with self._lock:
            self._pending_requests.pop(request_id, None)
        self._callbacks.pop(request_id, None)


_hitl_gate: Optional[HITLApprovalGate] = None


def get_hitl_gate() -> HITLApprovalGate:
    global _hitl_gate
    if _hitl_gate is None:
        _hitl_gate = HITLApprovalGate()
    return _hitl_gate

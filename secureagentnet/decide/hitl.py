import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)

HITL_TIMEOUT_SECONDS = 60

# How long an operator's decision stays redeemable by a re-issued action. Long
# enough for a human to read the request and re-run the command; short enough
# that yesterday's approval cannot authorise today's action.
HITL_DECISION_TTL_SECONDS = 900


def fingerprint_action(agent_id: str, action_name: str, target_resource: str,
                       payload: Optional[Dict[str, Any]] = None) -> str:
    """Stable identity for one action, so a retry can be matched to its decision.

    The payload is included: approving ``execute_code`` once must not authorise
    every future ``execute_code`` on the same target. Serialisation is sorted and
    falls back to ``repr`` so an unserialisable payload still hashes consistently
    rather than raising inside the decision path.
    """
    try:
        payload_repr = json.dumps(payload or {}, sort_keys=True, default=repr)
    except Exception:
        payload_repr = repr(payload)
    material = "\x1f".join((
        str(agent_id or ""), str(action_name or ""),
        str(target_resource or ""), payload_repr,
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class HITLDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    PENDING = "pending"


def _as_decision(status: Optional[str]) -> HITLDecision:
    """Map a stored status string to a decision, tolerating unknown values."""
    try:
        return HITLDecision(status)
    except ValueError:
        return HITLDecision.TIMED_OUT


# The repository is imported lazily and every call degrades to None on failure,
# so the gate still works in unit tests and installs with no database wired up.

def _repo():
    try:
        from secureagentnet.database.repositories import HITLRepository
        return HITLRepository
    except Exception:
        return None


def _repo_save(req: Dict[str, Any]) -> bool:
    repo = _repo()
    return bool(repo and repo.save(req))


def _repo_get(request_id: str) -> Optional[Dict[str, Any]]:
    repo = _repo()
    return repo.get(request_id) if repo else None


def _repo_list(status: Optional[str] = None) -> list:
    repo = _repo()
    return repo.list_all(status) if repo else []


def _repo_set_decision(request_id: str, status: str, operator: str) -> Optional[Dict[str, Any]]:
    repo = _repo()
    return repo.set_decision(request_id, status, operator) if repo else None


def _repo_consume(fingerprint: str, max_age_seconds: int) -> Optional[Dict[str, Any]]:
    repo = _repo()
    return repo.consume_decision(fingerprint, max_age_seconds) if repo else None


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
        return len(self.get_all_pending())

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

    def consume_decision(self, fingerprint: str,
                         max_age_seconds: int = HITL_DECISION_TTL_SECONDS
                         ) -> Optional[Dict[str, Any]]:
        """Redeem a standing operator decision for this exact action, if any.

        An escalation is raised by a one-shot process that exits while the
        operator is still deciding, so the approval has to be honoured by the
        *next* attempt rather than the one that raised it. Without this, approving
        and re-running would simply escalate again — the approval would never
        take effect.

        The decision is single-use: it is stamped consumed as it is read, so it
        authorises one execution rather than becoming a standing exemption.
        """
        row = _repo_consume(fingerprint, max_age_seconds)
        if row is None:
            return None
        logger.info(
            "HITL: redeeming %s decision %s for action '%s' (decided by %s)",
            row.get("status"), row.get("request_id"), row.get("action_name"),
            row.get("decided_by"),
        )
        return row

    def create_pending_request(
        self,
        request_id: str,
        agent_id: str,
        action_name: str,
        target_resource: str,
        intent_summary: str,
        risk_score: float,
        reason: str,
        request_fingerprint: Optional[str] = None,
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
            "request_fingerprint": request_fingerprint,
        }
        persisted = _repo_save(req)
        # Remember whether this request reached shared storage. Where it did, the
        # DB row is authoritative and the local copy is only a cache — another
        # process may decide the request without this one ever hearing about it.
        req["_persisted"] = persisted
        with self._lock:
            self._pending_requests[request_id] = req
        if not persisted:
            logger.warning(
                "HITL: request %s is in-process only — no database is reachable, so "
                "it cannot be resolved from another process (e.g. `san hitl approve`)",
                request_id,
            )
        logger.info(
            "HITL: action '%s' by agent %s queued for approval (risk=%.2f)",
            action_name, agent_id, risk_score,
        )
        return request_id

    def _decide(self, request_id: str, decision: HITLDecision, operator: str) -> HITLDecision:
        """Resolve a request, preferring the shared DB row over the local cache.

        The DB write is conditional on the row still being ``pending``, so two
        operators racing to approve and deny cannot both win.
        """
        row = _repo_set_decision(request_id, decision.value, operator)
        if row is not None:
            with self._lock:
                cached = self._pending_requests.get(request_id)
                if cached is not None:
                    cached.update(row)
            logger.info("HITL: request %s %s by %s", request_id, decision.value.upper(), operator)
            self._invoke_callback(request_id, decision)
            return decision

        # Not resolvable in the DB — either it was already decided there, or no
        # DB is configured and the request only exists in this process.
        persisted = _repo_get(request_id)
        if persisted is not None:
            return _as_decision(persisted["status"])

        with self._lock:
            req = self._pending_requests.get(request_id)
            if not req:
                return HITLDecision.TIMED_OUT
            if req["status"] != HITLDecision.PENDING.value:
                return _as_decision(req["status"])
            req["status"] = decision.value
            req["decision_at"] = datetime.now(timezone.utc).isoformat()
            req["decided_by"] = operator
        logger.info("HITL: request %s %s by %s", request_id, decision.value.upper(), operator)
        self._invoke_callback(request_id, decision)
        return decision

    def approve(self, request_id: str, operator: str = "cli") -> HITLDecision:
        return self._decide(request_id, HITLDecision.APPROVED, operator)

    def deny(self, request_id: str, operator: str = "cli") -> HITLDecision:
        return self._decide(request_id, HITLDecision.DENIED, operator)

    def wait_for_decision(self, request_id: str, timeout: int = HITL_TIMEOUT_SECONDS) -> HITLDecision:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self._current_status(request_id)
            if status is None:
                return HITLDecision.TIMED_OUT
            if status != HITLDecision.PENDING.value:
                return _as_decision(status)
            time.sleep(0.5)

        logger.warning("HITL: request %s timed out after %ds — denying", request_id, timeout)
        self.deny(request_id, "timeout")
        return HITLDecision.TIMED_OUT

    def _current_status(self, request_id: str) -> Optional[str]:
        """Status from the shared DB if present, else the local cache."""
        persisted = _repo_get(request_id)
        if persisted is not None:
            return persisted["status"]
        with self._lock:
            req = self._pending_requests.get(request_id)
            return req["status"] if req else None

    def get_pending_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        persisted = _repo_get(request_id)
        if persisted is not None:
            return persisted
        with self._lock:
            return self._pending_requests.get(request_id)

    def get_all_pending(self) -> list:
        """Every pending request visible to this endpoint, from any process.

        Persisted requests come from the DB alone — a local cache entry can be
        stale the moment another process decides it. Only requests that never
        reached storage are served from memory.
        """
        by_id: Dict[str, Dict[str, Any]] = {}
        with self._lock:
            for r in self._pending_requests.values():
                if r["status"] == HITLDecision.PENDING.value and not r.get("_persisted"):
                    by_id[r["request_id"]] = r
        for r in _repo_list("pending"):
            by_id[r["request_id"]] = r
        return sorted(by_id.values(), key=lambda r: r.get("created_at") or "", reverse=True)

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

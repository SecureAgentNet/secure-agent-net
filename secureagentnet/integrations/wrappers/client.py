"""Generic Python client for routing agent actions through the SecureAgentNet daemon."""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests

from secureagentnet.daemon.config import get_daemon_settings

logger = logging.getLogger("SecureAgentNet.SDK")


# The one verdict that permits a governed tool to run. Everything else — a block,
# an escalation to human review, an infrastructure error, or any status added to
# the pipeline later — must not execute.
ALLOWED_STATUS = "success"


def is_allowed(result: dict) -> bool:
    """True only for an explicit approval.

    Deliberately an allow-list. The wrappers used to test for the two refusal
    statuses they knew about and execute otherwise, so ``escalated`` — the verdict
    DECIDE returns when it parks an action for human approval — matched neither
    branch and the tool ran anyway. The pipeline had already denied the action and
    torn down its sandbox unexecuted; the tool body then ran locally regardless.
    Any status this function does not recognise now refuses.
    """
    return result.get("status") == ALLOWED_STATUS


def format_denial(result: dict) -> str:
    """Render a non-approval for an agent's tool output.

    Includes the pipeline's remediation lines when it supplied them, so a refusal
    tells the developer how to authorise the call instead of just saying no.
    """
    status = str(result.get("status") or "unknown")
    reason = result.get("reason") or "refused by security policy"

    if status == "escalated":
        request_id = (result.get("metadata") or {}).get("hitl_request_id", "")
        message = f"[HELD by SecureAgentNet — awaiting human approval] {reason}"
        if request_id:
            message += (f"\nReview it with:\n  san hitl approve {request_id}"
                        f"\n  san hitl deny {request_id}")
    elif status == "error":
        message = f"[ERROR] {reason}"
    else:
        message = f"[BLOCKED by SecureAgentNet] {reason}"

    remediation = result.get("remediation") or []
    if remediation:
        message += "\n" + "\n".join(str(line) for line in remediation)
    return message


class InterceptClient:
    """Minimal synchronous client for the daemon intercept endpoint."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, timeout: float = 30.0):
        settings = get_daemon_settings()
        self.host = host or settings.daemon_host
        self.port = port or settings.daemon_port
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def intercept(
        self,
        agent_id: str,
        action_name: str,
        target_resource: str,
        intent_summary: str,
        payload: Optional[Dict[str, Any]] = None,
        command: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "action_name": action_name,
            "target_resource": target_resource,
            "intent_summary": intent_summary,
            "payload": payload or {},
        }
        if command is not None:
            body["command"] = command

        try:
            resp = requests.post(self._url("/v1/intercept"), json=body, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("SecureAgentNet daemon unreachable: %s", exc)
            return {
                "status": "error",
                "reason": f"Daemon unreachable: {exc}",
                "correlation_id": "",
            }


def secureagentnet_intercept(
    agent_id: str,
    action_name: str,
    target_resource: str,
    intent_summary: str,
    payload: Optional[Dict[str, Any]] = None,
    command: Optional[str] = None,
) -> Dict[str, Any]:
    """One-shot helper to send an action to the daemon for evaluation."""
    return InterceptClient().intercept(
        agent_id=agent_id,
        action_name=action_name,
        target_resource=target_resource,
        intent_summary=intent_summary,
        payload=payload,
        command=command,
    )

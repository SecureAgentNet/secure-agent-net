"""Generic Python client for routing agent actions through the SecureAgentNet daemon."""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests

from secureagentnet.daemon.config import get_daemon_settings

logger = logging.getLogger("SecureAgentNet.SDK")


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

"""HTTP client used by the desktop GUI to talk to the daemon."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from secureagentnet.daemon.config import get_daemon_settings

logger = logging.getLogger("SecureAgentNet.Desktop.Client")


class DaemonClient:
    """Thin synchronous client for the daemon middleware API."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        settings = get_daemon_settings()
        self.host = host or settings.daemon_host
        self.port = port or settings.daemon_port
        self.base_url = f"http://{self.host}:{self.port}"
        self.timeout = 6

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def is_alive(self) -> bool:
        try:
            resp = requests.get(self._url("/health"), timeout=2)
            return resp.status_code == 200
        except Exception:
            return False

    def status(self) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(self._url("/v1/status"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug("Failed to get daemon status: %s", exc)
            return None

    def registered_agents(self) -> List[Dict[str, Any]]:
        try:
            resp = requests.get(self._url("/v1/agents"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    def agent_detail(self, agent_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(self._url(f"/v1/agents/{agent_id}"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def service_health(self) -> Dict[str, str]:
        try:
            resp = requests.get(self._url("/v1/health"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json() or {}
        except Exception:
            return {}

    def hitl_pending(self) -> List[Dict[str, Any]]:
        try:
            resp = requests.get(self._url("/v1/hitl/pending"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("pending", [])
        except Exception:
            return []

    def hitl_decide(self, request_id: str, approve: bool) -> Optional[Dict[str, Any]]:
        verb = "approve" if approve else "deny"
        try:
            resp = requests.post(self._url(f"/v1/hitl/{request_id}/{verb}"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug("HITL %s failed: %s", verb, exc)
            return None

    def intercept(
        self,
        agent_id: str,
        action_name: str,
        target_resource: str,
        intent_summary: str,
        payload: Optional[Dict[str, Any]] = None,
        command: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        body = {
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
        except Exception as exc:
            logger.error("Intercept request failed: %s", exc)
            return {"status": "error", "reason": str(exc), "correlation_id": ""}

    def scan(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        # A scan can take longer than a normal request, so it gets its own
        # generous timeout (and the desktop runs it on a background thread).
        try:
            resp = requests.post(self._url("/v1/scan"), timeout=timeout or 120)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("Scan request failed: %s", exc)
            return None

    def discovered_agents(self) -> List[Dict[str, Any]]:
        try:
            resp = requests.get(self._url("/v1/agents/discovered"), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("Discovered agents request failed: %s", exc)
            return []

    def alert_stream_url(self) -> str:
        return f"ws://{self.host}:{self.port}/v1/alerts"

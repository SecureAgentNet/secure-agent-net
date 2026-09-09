"""HTTP client used by the desktop GUI to talk to the daemon."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter

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

        # One pooled session for the whole app. The module-level requests.get()
        # helpers build a fresh Session per call — a new TCP connection, a new
        # adapter, no keep-alive — and the desktop makes several calls a second.
        # A single session with a keep-alive pool removes that per-call setup.
        self._session = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
        self._session.mount("http://", adapter)
        self._session.headers["Connection"] = "keep-alive"

    def close(self) -> None:
        """Release the pooled connections (called on app shutdown)."""
        try:
            self._session.close()
        except Exception:
            pass

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _get(self, path: str, timeout: Optional[float] = None):
        return self._session.get(self._url(path), timeout=timeout or self.timeout)

    def is_alive(self) -> bool:
        try:
            resp = self._get("/health", timeout=2)
            return resp.status_code == 200
        except Exception:
            return False

    def status(self) -> Optional[Dict[str, Any]]:
        try:
            resp = self._get("/v1/status")
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug("Failed to get daemon status: %s", exc)
            return None

    def registered_agents(self) -> List[Dict[str, Any]]:
        try:
            resp = self._get("/v1/agents")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    def agent_contracts(self) -> List[Dict[str, Any]]:
        try:
            resp = self._get("/v1/agent-contracts")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    def agent_detail(self, agent_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self._get(f"/v1/agents/{agent_id}")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def service_health(self) -> Dict[str, str]:
        try:
            resp = self._get("/v1/health")
            resp.raise_for_status()
            return resp.json() or {}
        except Exception:
            return {}

    def hitl_pending(self) -> List[Dict[str, Any]]:
        try:
            resp = self._get("/v1/hitl/pending")
            resp.raise_for_status()
            return resp.json().get("pending", [])
        except Exception:
            return []

    def hitl_decide(self, request_id: str, approve: bool,
                    operator: Optional[str] = None) -> Optional[Dict[str, Any]]:
        verb = "approve" if approve else "deny"
        try:
            resp = self._session.post(
                self._url(f"/v1/hitl/{request_id}/{verb}"),
                params={"operator": operator} if operator else None,
                timeout=self.timeout)
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
            resp = self._session.post(self._url("/v1/intercept"), json=body, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("Intercept request failed: %s", exc)
            return {"status": "error", "reason": str(exc), "correlation_id": ""}

    def scan(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        # A scan can take longer than a normal request, so it gets its own
        # generous timeout (and the desktop runs it on a background thread).
        try:
            resp = self._session.post(self._url("/v1/scan"), timeout=timeout or 120)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("Scan request failed: %s", exc)
            return None

    def discovered_agents(self) -> List[Dict[str, Any]]:
        try:
            resp = self._get("/v1/agents/discovered")
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("Discovered agents request failed: %s", exc)
            return []

    def recent_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Backfill for the activity panels — the audit trail before this launch."""
        try:
            resp = self._get(f"/v1/events/recent?limit={int(limit)}")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    def alert_stream_url(self) -> str:
        return f"ws://{self.host}:{self.port}/v1/alerts"

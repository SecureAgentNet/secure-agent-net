"""Optional cloud-based risk scanner with local fallback.

The daemon can send high-stakes action payloads to a configured remote endpoint
for an additional risk verdict. If the remote service is unavailable or
unconfigured, the scanner falls back to the local Ollama semantic evaluator or
to a deterministic demo mode.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional

import requests

from secureagentnet.core.config import get_settings
from secureagentnet.daemon.config import get_daemon_settings

logger = logging.getLogger("SecureAgentNet.CloudScanner")


class CloudScanResult:
    def __init__(self, risk_score: float, verdict: str, reason: str, source: str):
        self.risk_score = risk_score
        self.verdict = verdict
        self.reason = reason
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "reason": self.reason,
            "source": self.source,
        }


class CloudScanner:
    """Remote/cloud risk scanner with local fallback."""

    def __init__(self):
        daemon_settings = get_daemon_settings()
        self.url = daemon_settings.cloud_scan_url
        self.api_key = daemon_settings.cloud_scan_api_key
        self.timeout = daemon_settings.cloud_scan_timeout_seconds
        self.demo_mode = daemon_settings.cloud_scan_demo_mode

    def scan(self, agent_id: str, action_name: str, payload: Dict[str, Any], intent: str) -> CloudScanResult:
        # Allow demo mode to be toggled via environment even if settings singleton is cached.
        demo = self.demo_mode or os.environ.get("SAN_CLOUD_SCAN_DEMO_MODE", "").lower() in ("1", "true", "yes")
        if demo:
            return self._demo_scan(action_name, payload, intent)

        if self.url:
            try:
                return self._remote_scan(agent_id, action_name, payload, intent)
            except Exception as exc:
                logger.warning("Remote cloud scan failed, falling back to local: %s", exc)

        return self._local_fallback(agent_id, action_name, payload, intent)

    def _remote_scan(self, agent_id: str, action_name: str, payload: Dict[str, Any], intent: str) -> CloudScanResult:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body = {
            "agent_id": agent_id,
            "action_name": action_name,
            "intent": intent,
            "payload": payload,
        }
        resp = requests.post(self.url, headers=headers, json=body, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return CloudScanResult(
            risk_score=float(data.get("risk_score", 0.0)),
            verdict=data.get("verdict", "unknown"),
            reason=data.get("reason", "cloud scan"),
            source="cloud",
        )

    def _demo_scan(self, action_name: str, payload: Dict[str, Any], intent: str) -> CloudScanResult:
        """Deterministic demo mode for presentations without external services."""
        text = f"{action_name} {intent} {json.dumps(payload, default=str, sort_keys=True)}".lower()
        digest = hashlib.sha256(text.encode()).hexdigest()
        # Deterministic but varied demo verdicts.
        if any(kw in text for kw in ("exfiltrate", "delete_database", "format_drive", "prompt_injection")):
            return CloudScanResult(0.95, "MALICIOUS", "Demo cloud scanner detected malicious pattern", "cloud-demo")
        if any(kw in text for kw in ("write_file", "network_access", "execute_code")):
            return CloudScanResult(0.45, "SUSPICIOUS", "Demo cloud scanner flagged elevated-capability action", "cloud-demo")
        return CloudScanResult(0.05, "SAFE", "Demo cloud scanner found no risk", "cloud-demo")

    def _local_fallback(self, agent_id: str, action_name: str, payload: Dict[str, Any], intent: str) -> CloudScanResult:
        """Use the local Ollama semantic evaluator if available."""
        try:
            from secureagentnet.decide.semantic_evaluator import SemanticEvaluator
            from secureagentnet.decide.models import EvaluationRequest

            settings = get_settings()
            evaluator = SemanticEvaluator()
            request = EvaluationRequest(
                agent_id=agent_id,
                action_name=action_name,
                target_resource=payload.get("resource", "unknown"),
                intent_summary=intent,
                payload=payload,
                commissioned_goal=None,
            )
            result = evaluator.evaluate(request)
            return CloudScanResult(
                risk_score=result.risk_score,
                verdict=result.verdict if hasattr(result, "verdict") else ("MALICIOUS" if result.risk_score >= 0.7 else "SAFE"),
                reason=result.reason,
                source="local-llm",
            )
        except Exception as exc:
            logger.debug("Local LLM fallback unavailable: %s", exc)
            return CloudScanResult(0.0, "SAFE", "No cloud or local scan available; default allow", "fallback")

"""Daemon → Cloud Console reporting client.

Forwards *metadata only* to the console: the outbound event is built from the
allowlist in `secureagentnet.cloud.protocol`, and the concrete target/resource
is reduced to a coarse category here (never the raw path). An on-disk queue
makes reporting survive the console being unreachable.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("SecureAgentNet.Daemon.CloudReporter")

# Fixed, coarse vocabulary — a reported target is always one of these, so a raw
# resource path or URL can never leave the host via the target field.
_TARGET_VOCAB = ("credentials", "payments", "network", "filesystem", "database",
                 "shell", "messaging", "other")


def categorize_target(resource: Optional[str], action: Optional[str]) -> Optional[str]:
    if not resource:
        return None
    r = resource.lower()
    if any(k in r for k in ("/.ssh", "id_rsa", "credential", ".aws", ".env", "secret", "shadow", "passwd", "token", "key")):
        return "credentials"
    if any(k in r for k in ("payroll", "payment", "bank", "transfer", "invoice", "billing")):
        return "payments"
    if r.startswith(("http://", "https://")) or any(k in r for k in ("webhook", "api.", "smtp", "://")):
        return "network"
    if any(k in r for k in ("mail", "email", "slack", "message")):
        return "messaging"
    if any(k in r for k in (".db", "database", "sql", "postgres", "mysql", "sqlite")):
        return "database"
    if "shell" in r or (action or "").lower() in ("execute", "run", "exec"):
        return "shell"
    if r.startswith(("/", "./", "~", "\\")) or ":/" in r or "file" in r:
        return "filesystem"
    return "other"


def alert_to_event(alert: dict) -> dict:
    """Map a daemon AlertManager alert to an allowlisted console event dict."""
    md = alert.get("metadata", {}) or {}
    sev = alert.get("severity", "INFO")
    return {
        "kind": "alert",
        "severity": sev,
        "decision": "deny" if sev in ("WARNING", "CRITICAL") else None,
        "risk_score": md.get("risk_score"),
        "reason": md.get("reason") or alert.get("message"),
        "agent_ref": md.get("agent_name") or md.get("agent_id"),
        "action_name": md.get("action"),
        "target_type": categorize_target(md.get("resource"), md.get("action")),
        "occurred_at": alert.get("timestamp"),
    }


@dataclass
class CloudCreds:
    console_url: str
    endpoint_id: str
    api_key: str

    @staticmethod
    def _path(data_dir) -> Path:
        return Path(data_dir) / "cloud.json"

    @classmethod
    def load(cls, data_dir) -> Optional["CloudCreds"]:
        p = cls._path(data_dir)
        if not p.exists():
            return None
        try:
            return cls(**json.loads(p.read_text()))
        except Exception as exc:
            logger.warning("Failed to read cloud creds: %s", exc)
            return None

    def save(self, data_dir) -> None:
        p = self._path(data_dir)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(asdict(self), indent=2))
        try:
            os.chmod(p, 0o600)  # contains the API key
        except OSError:
            pass


class CloudReporter:
    """Owns the outbound queue + transport. `client` is an httpx.AsyncClient
    (real in the daemon; an ASGITransport client in tests) so it is fully
    testable in-process."""

    def __init__(self, client, creds: CloudCreds, data_dir, interval: int = 15,
                 command_handler=None, agent_provider=None):
        self.client = client
        self.creds = creds
        self.data_dir = Path(data_dir)
        self.interval = interval
        self.queue_path = self.data_dir / "cloud_queue.jsonl"
        self.command_handler = command_handler  # called with each pulled command
        self.agent_provider = agent_provider     # () -> list[dict] of allowlisted agent fields
        self._stop = False

    def _collect_agents(self) -> list:
        if self.agent_provider is None:
            return []
        try:
            return self.agent_provider() or []
        except Exception as exc:
            logger.debug("agent_provider failed: %s", exc)
            return []

    def _headers(self) -> dict:
        return {"X-SAN-Endpoint-Key": self.creds.api_key}

    def enqueue_event(self, event: dict) -> None:
        """Validate against the allowlist, then persist to the offline queue.
        A non-allowlisted field raises here — it can never reach the wire."""
        from secureagentnet.cloud.protocol import EventIn
        EventIn(**event)  # ValidationError if anything outside the allowlist sneaks in
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with open(self.queue_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    async def flush(self) -> int:
        """Send queued events. On failure they are re-queued (offline-safe)."""
        if not self.queue_path.exists() or self.queue_path.stat().st_size == 0:
            return 0
        sending = self.queue_path.with_suffix(".sending")
        os.replace(self.queue_path, sending)  # new enqueues start a fresh queue file
        events = [json.loads(l) for l in sending.read_text().splitlines() if l.strip()]
        try:
            resp = await self.client.post("/api/v1/ingest",
                                          json={"events": events}, headers=self._headers())
            resp.raise_for_status()
            sending.unlink(missing_ok=True)
            return len(events)
        except Exception as exc:
            logger.warning("Cloud flush failed (%s); re-queuing %d events", exc, len(events))
            with open(self.queue_path, "a", encoding="utf-8") as f:
                for e in events:
                    f.write(json.dumps(e, default=str) + "\n")
            sending.unlink(missing_ok=True)
            return 0

    async def heartbeat(self, agents: Optional[List[dict]] = None,
                        threats_blocked: Optional[int] = None) -> List[dict]:
        """Heartbeat + pull any pending commands (kill-switch handled in 3.5)."""
        body = {"agents": agents or []}
        if threats_blocked is not None:
            body["threats_blocked"] = threats_blocked
        try:
            resp = await self.client.post("/api/v1/heartbeat", json=body, headers=self._headers())
            resp.raise_for_status()
            return resp.json().get("commands", [])
        except Exception as exc:
            logger.debug("Heartbeat failed: %s", exc)
            return []

    async def consume_alerts(self, alert_manager) -> None:
        """Subscribe to the local alert stream and forward each alert up."""
        queue = await alert_manager.subscribe()
        try:
            while not self._stop:
                alert = await queue.get()
                try:
                    self.enqueue_event(alert_to_event(alert))
                except Exception as exc:
                    logger.warning("Skipping unmappable alert: %s", exc)
        finally:
            await alert_manager.unsubscribe(queue)

    async def ack_command(self, command_id: str, status: str, result: str) -> None:
        try:
            await self.client.post(
                f"/api/v1/commands/{command_id}/ack",
                json={"status": status, "result": (result or "")[:500]},
                headers=self._headers(),
            )
        except Exception as exc:
            logger.warning("Failed to ack command %s: %s", command_id, exc)

    async def handle_command(self, command: dict) -> None:
        """Execute a pulled command via the registered handler, then ack the result."""
        import inspect
        ok, result = False, "no command handler registered"
        if self.command_handler is not None:
            try:
                res = self.command_handler(command)
                if inspect.isawaitable(res):
                    res = await res
                ok, result = True, str(res)
            except Exception as exc:
                ok, result = False, str(exc)
                logger.error("Command %s failed: %s", command.get("id"), exc)
        await self.ack_command(command.get("id"), "done" if ok else "failed", result)

    async def run_loop(self) -> None:
        import asyncio
        while not self._stop:
            await self.flush()
            for command in await self.heartbeat(agents=self._collect_agents()):
                await self.handle_command(command)
            await asyncio.sleep(self.interval)

    def stop(self) -> None:
        self._stop = True

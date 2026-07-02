"""Continuous background discovery of embedded AI agents."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from secureagentnet.daemon.alerts import AlertManager
from secureagentnet.daemon.config import DaemonSettings, get_daemon_settings
from secureagentnet.identify.agent_discovery import AgentDiscoveryOrchestrator
from secureagentnet.identify.capability_profiler import CapabilityProfiler
from secureagentnet.identify.identity_registry import IdentityRegistry

logger = logging.getLogger("SecureAgentNet.Daemon.Discovery")


class DiscoveryScheduler:
    """Periodically scans the host for AI agents and optionally registers them."""

    def __init__(
        self,
        settings: Optional[DaemonSettings] = None,
        alert_manager: Optional[AlertManager] = None,
    ):
        self.settings = settings or get_daemon_settings()
        self.alert_manager = alert_manager
        self.interval_seconds = self.settings.discovery_interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self.last_results: List[Dict[str, Any]] = []
        self.last_scan_at: Optional[str] = None

    async def start(self) -> None:
        logger.info("Starting discovery scheduler (interval=%ss)", self.interval_seconds)
        await self.run_once()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        logger.info("Stopping discovery scheduler")
        self._stop_event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.interval_seconds,
                )
            except asyncio.TimeoutError:
                await self.run_once()

    async def run_once(self) -> List[Dict[str, Any]]:
        logger.info("Running agent discovery scan")
        try:
            discovered = await asyncio.to_thread(
                AgentDiscoveryOrchestrator.discover_all, scanners=None, deduplicate=True
            )
        except Exception as exc:
            logger.exception("Discovery scan failed: %s", exc)
            return []

        results: List[Dict[str, Any]] = []
        registered = 0
        for agent in discovered:
            record = asdict(agent)
            record["registered"] = False
            existing = IdentityRegistry.get_agent_by_name(agent.name)
            if not existing:
                try:
                    agent_data = {
                        "name": agent.name,
                        "type": agent.framework,
                        "description": f"Discovered via {agent.source} scanner",
                        "capabilities": {c: True for c in (agent.capabilities or [])},
                        "metadata": {
                            "discovered_by": agent.source,
                            "discovered_at": agent.discovered_at,
                        },
                        "created_by": "auto-discover",
                    }
                    result = IdentityRegistry.register_agent(agent_data)
                    for cap in agent.capabilities or []:
                        CapabilityProfiler.add_capability(result["agent_id"], cap)
                    record["registered"] = True
                    record["agent_id"] = result["agent_id"]
                    registered += 1
                except Exception as exc:
                    logger.warning("Failed to auto-register discovered agent %s: %s", agent.name, exc)
            else:
                record["agent_id"] = existing["agent_id"]
            results.append(record)

        # Prune stale auto-discovered agents that are no longer present. This is
        # what lets a corrected agent-definition propagate through the system:
        # agents mis-detected by an earlier scan (or genuinely gone) are removed
        # rather than persisting forever. Manually registered / commissioned
        # agents (created_by != "auto-discover") are never touched.
        pruned = 0
        current_names = {a.name for a in discovered}
        for existing in IdentityRegistry.list_agents():
            if (existing.get("created_by") == "auto-discover"
                    and existing.get("name") not in current_names):
                try:
                    IdentityRegistry.deregister_agent(existing["agent_id"])
                    pruned += 1
                except Exception as exc:
                    logger.debug("Failed to prune stale agent %s: %s", existing.get("name"), exc)
        if pruned:
            logger.info("Pruned %s stale auto-discovered agent(s)", pruned)

        self.last_results = results
        self.last_scan_at = datetime.now(timezone.utc).isoformat()

        if self.alert_manager and (discovered or registered):
            await self.alert_manager.emit(
                severity="INFO",
                title="System Scan Complete",
                message=f"Discovered {len(discovered)} AI agent(s); auto-registered {registered}.",
                metadata={"discovered": len(discovered), "registered": registered},
                notify_desktop=False,
            )

        logger.info("Discovery scan complete: %s discovered, %s registered", len(discovered), registered)
        return results

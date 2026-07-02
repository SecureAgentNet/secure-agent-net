"""FastAPI middleware API exposed by the SecureAgentNet daemon."""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from secureagentnet.core.pipeline import ITCDPipeline
from secureagentnet.daemon.alerts import AlertManager
from secureagentnet.daemon.config import DaemonSettings, get_daemon_settings
from secureagentnet.daemon.discovery_scheduler import DiscoveryScheduler
from secureagentnet.database.connection import init_database
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.track.models import AgentActionRequest

logger = logging.getLogger("SecureAgentNet.Daemon.API")


class InterceptRequest(BaseModel):
    agent_id: str
    action_name: str = "execute"
    target_resource: str = "shell"
    intent_summary: str = "Intercepted agent action"
    payload: Dict[str, Any] = Field(default_factory=dict)
    command: Optional[str] = None


class InterceptResponse(BaseModel):
    status: str
    correlation_id: str
    reason: Optional[str] = None
    risk_score: Optional[float] = None
    evaluated_by: Optional[str] = None
    phase: Optional[str] = None
    vault_receipt: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error_details: Optional[str] = None


class DaemonStatus(BaseModel):
    status: str = "ok"
    started_at: str
    agents_total: int
    agents_active: int
    threats_blocked: int
    uptime_seconds: float
    version: str = "2.0.0"


class DaemonState:
    """Shared state across the daemon process."""

    def __init__(self, settings: Optional[DaemonSettings] = None):
        self.settings = settings or get_daemon_settings()
        self.started_at = datetime.now(timezone.utc)
        self.pipeline = ITCDPipeline()
        self.alert_manager = AlertManager(settings=self.settings)
        self.discovery_scheduler: Optional[DiscoveryScheduler] = None
        self.threats_blocked = 0
        self.cloud_reporter = None          # set in lifespan if the daemon is enrolled
        self._cloud_tasks: list = []
        self._cloud_client = None

    def get_status(self) -> DaemonStatus:
        uptime = (datetime.now(timezone.utc) - self.started_at).total_seconds()
        return DaemonStatus(
            started_at=self.started_at.isoformat(),
            agents_total=IdentityRegistry.get_total_count(),
            agents_active=IdentityRegistry.get_active_count(),
            threats_blocked=self.threats_blocked,
            uptime_seconds=uptime,
        )


_state: Optional[DaemonState] = None


def get_state() -> DaemonState:
    if _state is None:
        raise RuntimeError("Daemon state has not been initialized")
    return _state


def create_app(settings: Optional[DaemonSettings] = None) -> FastAPI:
    global _state
    _state = DaemonState(settings=settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Daemon API starting up")
        app.state.daemon_state = _state
        init_database()
        IdentityRegistry.initialize()
        LogIndexer.initialize()
        _state.discovery_scheduler = DiscoveryScheduler(
            settings=_state.settings,
            alert_manager=_state.alert_manager,
        )
        await _state.discovery_scheduler.start()
        await _start_cloud_reporter(_state)
        yield
        logger.info("Daemon API shutting down")
        if _state.discovery_scheduler:
            await _state.discovery_scheduler.stop()
        await _stop_cloud_reporter(_state)

    app = FastAPI(title="SecureAgentNet Daemon", version="2.0.0", lifespan=lifespan)

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok", "service": "secureagentnet-daemon"}

    @app.get("/v1/status")
    async def status() -> DaemonStatus:
        return get_state().get_status()

    @app.get("/v1/health")
    async def service_health() -> Dict[str, str]:
        from secureagentnet.daemon.health import probe_services
        return probe_services()

    # ── Human-in-the-loop review queue ──
    @app.get("/v1/hitl/pending")
    async def hitl_pending() -> Dict[str, Any]:
        from secureagentnet.decide.hitl import get_hitl_gate
        return {"pending": get_hitl_gate().get_all_pending()}

    @app.post("/v1/hitl/{request_id}/approve")
    async def hitl_approve(request_id: str) -> Dict[str, str]:
        from secureagentnet.decide.hitl import get_hitl_gate
        decision = get_hitl_gate().approve(request_id, "desktop")
        return {"request_id": request_id, "decision": getattr(decision, "value", str(decision))}

    @app.post("/v1/hitl/{request_id}/deny")
    async def hitl_deny(request_id: str) -> Dict[str, str]:
        from secureagentnet.decide.hitl import get_hitl_gate
        decision = get_hitl_gate().deny(request_id, "desktop")
        return {"request_id": request_id, "decision": getattr(decision, "value", str(decision))}

    @app.post("/v1/intercept", response_model=InterceptResponse)
    async def intercept(req: InterceptRequest) -> InterceptResponse:
        state = get_state()
        command = req.command or req.payload.get("command", "")
        request = AgentActionRequest(
            action_name=req.action_name,
            target_resource=req.target_resource,
            intent_summary=req.intent_summary,
            payload=req.payload,
        )

        try:
            result = await state.pipeline.execute_agent_action(req.agent_id, request, command)
        except Exception as exc:
            logger.exception("Pipeline error during intercept")
            result = {
                "status": "error",
                "reason": str(exc),
                "evaluated_by": "Daemon",
                "phase": "DAEMON",
                "correlation_id": "",
            }

        is_block = result.get("status") in ("blocked", "error")
        is_critical = is_block and (result.get("risk_score", 0.0) >= 0.7 or "CRITICAL" in str(result.get("reason", "")))

        if is_block:
            state.threats_blocked += 1

        if is_block:
            severity = "CRITICAL" if is_critical else "WARNING"
            agent = IdentityRegistry.get_agent(req.agent_id)
            agent_name = agent.get("name", req.agent_id) if agent else req.agent_id
            trust_score = agent.get("trust_score", 0.0) if agent else 0.0
            await state.alert_manager.emit(
                severity=severity,
                title=f"{'CRITICAL: ' if is_critical else ''}Action Blocked",
                message=f"Agent '{agent_name}' attempted {req.action_name} on {req.target_resource}",
                metadata={
                    "agent_id": req.agent_id,
                    "agent_name": agent_name,
                    "action": req.action_name,
                    "resource": req.target_resource,
                    "reason": result.get("reason"),
                    "risk_score": result.get("risk_score"),
                    "trust_score": trust_score,
                    "correlation_id": result.get("correlation_id"),
                },
            )

        return InterceptResponse(
            status=result.get("status", "unknown"),
            correlation_id=result.get("correlation_id", ""),
            reason=result.get("reason"),
            risk_score=result.get("risk_score"),
            evaluated_by=result.get("evaluated_by"),
            phase=result.get("phase"),
            vault_receipt=result.get("vault_receipt"),
            data=result.get("data"),
            metadata=result.get("metadata", {}),
            error_details=result.get("error_details"),
        )

    @app.post("/v1/scan")
    async def scan() -> Dict[str, Any]:
        state = get_state()
        if state.discovery_scheduler:
            discovered = await state.discovery_scheduler.run_once()
            return {"status": "ok", "discovered": len(discovered)}
        return {"status": "error", "detail": "Discovery scheduler not available"}

    @app.get("/v1/agents/discovered")
    async def discovered() -> List[Dict[str, Any]]:
        state = get_state()
        if state.discovery_scheduler:
            return state.discovery_scheduler.last_results
        return []

    @app.get("/v1/agents")
    async def registered_agents() -> List[Dict[str, Any]]:
        """All agents known to the identity registry (registered + discovered),
        not just those currently running as live processes."""
        live = set()
        state = get_state()
        if state.discovery_scheduler:
            for d in state.discovery_scheduler.last_results:
                live.add(str(d.get("agent_id") or d.get("name", "")))
        out: List[Dict[str, Any]] = []
        for a in IdentityRegistry.list_agents():
            aid = str(a.get("agent_id", ""))
            is_live = aid in live or a.get("name", "") in live
            out.append({
                "agent_id": aid,
                "name": a.get("name", ""),
                "framework": a.get("type", ""),
                "type": a.get("type", ""),
                "source": "live" if is_live else (a.get("created_by") or "registered"),
                "status": a.get("status", ""),
                "trust_score": a.get("trust_score"),
                "capabilities": a.get("capabilities", {}),
                "live": is_live,
            })
        return out

    @app.get("/v1/agents/{agent_id}")
    async def agent_detail(agent_id: str) -> Dict[str, Any]:
        """Full detail for one agent: identity, capabilities, container resources,
        the enforced security profile, and a timestamped ITCD activity timeline."""
        a = IdentityRegistry.get_agent(agent_id)
        if not a:
            raise HTTPException(status_code=404, detail="Agent not found")

        caps = a.get("capabilities", {})
        if isinstance(caps, dict):
            cap_list = sorted(k for k, v in caps.items() if v)
        else:
            cap_list = [str(x) for x in (caps or [])]

        from secureagentnet.contain.resource_manager import ContainerResourceManager
        containers = ContainerResourceManager.get_agent_containers(agent_id)
        container = None
        for c in containers:
            if c.get("status") in ("running", "creating"):
                container = c
                break
        container = container or (containers[-1] if containers else None)
        quota = (container or {}).get("quota", {})
        live = None
        if container and container.get("status") == "running":
            live = _live_container_stats(container.get("container_id"))

        from secureagentnet.track.log_indexer import LogIndexer
        events = LogIndexer.query_by_agent(agent_id, limit=8)
        timeline = [{
            "time": e.get("timestamp", ""),
            "phase": str(e.get("phase", "") or ""),
            "event": e.get("event_type", ""),
            "summary": e.get("summary", ""),
            "severity": e.get("severity", ""),
        } for e in events]

        from secureagentnet.utils.platform import apparmor_available
        from pathlib import Path as _Path
        seccomp_ok = (_Path(__file__).resolve().parent.parent.parent
                      / "config" / "seccomp_profile.json").exists()

        return {
            "agent_id": agent_id,
            "name": a.get("name", ""),
            "type": a.get("type", ""),
            "framework": a.get("type", ""),
            "status": a.get("status", ""),
            "trust_score": a.get("trust_score"),
            "capabilities": cap_list,
            "registered_at": a.get("registered_at"),
            "last_seen": a.get("last_seen"),
            "current_phase": timeline[0]["phase"] if timeline else None,
            "container": {
                "container_id": (container or {}).get("container_id"),
                "status": (container or {}).get("status", "none"),
                "cpu_limit_cores": quota.get("cpu_limit"),
                "memory_limit_mb": quota.get("memory_limit_mb"),
            },
            "live": live,
            "security_profile": {
                "Read-only filesystem": True,
                "Seccomp profile active": seccomp_ok,
                "AppArmor enforced": apparmor_available(),
                "Network isolated": True,
                "Capabilities dropped": "ALL",
            },
            "timeline": timeline,
        }

    @app.websocket("/v1/alerts")
    async def alerts_ws(websocket: WebSocket):
        await websocket.accept()
        state = get_state()
        queue = await state.alert_manager.subscribe()
        try:
            # Send recent history first.
            for alert in state.alert_manager.recent_alerts(limit=20):
                await websocket.send_text(json.dumps(alert, default=str))
            while True:
                alert = await queue.get()
                await websocket.send_text(json.dumps(alert, default=str))
        except WebSocketDisconnect:
            pass
        finally:
            await state.alert_manager.unsubscribe(queue)

    return app


def _live_container_stats(container_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Best-effort live Docker stats for a running container. Returns None on any
    failure (Docker absent, container gone) so the caller degrades gracefully."""
    if not container_id:
        return None
    try:
        import docker
        client = docker.from_env()
        c = client.containers.get(container_id)
        if c.status != "running":
            return None
        s = c.stats(stream=False)
        cpu = s.get("cpu_stats", {}); pre = s.get("precpu_stats", {})
        cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage", [1])) or 1
        cpu_pct = (cpu_delta / sys_delta) * ncpu * 100 if sys_delta > 0 else 0.0
        mem = s.get("memory_stats", {})
        usage = mem.get("usage", 0); limit = mem.get("limit", 0)
        nets = s.get("networks", {}) or {}
        rx = sum(n.get("rx_bytes", 0) for n in nets.values())
        tx = sum(n.get("tx_bytes", 0) for n in nets.values())
        return {
            "cpu_percent": round(cpu_pct, 1),
            "memory_mb": round(usage / 1048576, 1),
            "memory_limit_mb": round(limit / 1048576) if limit else None,
            "rx_mb": round(rx / 1048576, 2),
            "tx_mb": round(tx / 1048576, 2),
        }
    except Exception:
        return None


async def _start_cloud_reporter(state: "DaemonState") -> None:
    """If this daemon has been enrolled (`san cloud enroll`), start forwarding
    metadata to the cloud console: alert stream + heartbeat loop."""
    import asyncio

    from secureagentnet.daemon.cloud_reporter import CloudCreds, CloudReporter

    creds = CloudCreds.load(state.settings.data_dir)
    if creds is None:
        logger.info("No cloud enrollment found — running standalone (no console reporting)")
        return
    try:
        import httpx
        client = httpx.AsyncClient(base_url=creds.console_url, timeout=10)

        def _command_handler(command: dict) -> str:
            # The only control action the console can issue (by design): trip the
            # local kill-switch the daemon already owns. Nothing else is honored.
            if command.get("type") == "kill_switch":
                state.pipeline.kill_switch.activate(triggered_by="cloud-console")
                logger.warning("Remote kill-switch ACTIVATED by cloud console (command %s)",
                               command.get("id"))
                return "kill-switch activated"
            return f"ignored unsupported command type: {command.get('type')}"

        def _agent_provider() -> list:
            # Report agent inventory (metadata only) so the console shows trust
            # scores and counts per endpoint.
            from secureagentnet.identify.identity_registry import IdentityRegistry
            out = []
            for a in IdentityRegistry.list_agents():
                out.append({
                    "agent_ref": a.get("name") or str(a.get("agent_id")),
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "trust_score": a.get("trust_score"),
                    "status": a.get("status"),
                })
            return out

        reporter = CloudReporter(
            client=client, creds=creds, data_dir=state.settings.data_dir,
            interval=getattr(state.settings, "cloud_report_interval_seconds", 15),
            command_handler=_command_handler,
            agent_provider=_agent_provider,
        )
        state.cloud_reporter = reporter
        state._cloud_client = client
        state._cloud_tasks = [
            asyncio.create_task(reporter.consume_alerts(state.alert_manager)),
            asyncio.create_task(reporter.run_loop()),
        ]
        logger.info("Cloud reporter started → %s (endpoint %s)",
                    creds.console_url, creds.endpoint_id)
    except Exception as exc:
        logger.error("Failed to start cloud reporter: %s", exc)


async def _stop_cloud_reporter(state: "DaemonState") -> None:
    if state.cloud_reporter is None:
        return
    state.cloud_reporter.stop()
    for task in state._cloud_tasks:
        task.cancel()
    if state._cloud_client is not None:
        try:
            await state._cloud_client.aclose()
        except Exception:
            pass

"""Prometheus metrics for SecureAgentNet observability.

Exposes counters and gauges for:
- Blocked/allowed request counts per phase
- HITL pending request count
- Anomaly scores per agent
- Circuit breaker state
- Kill-switch state
- Container sandbox counts
"""

from prometheus_client import Counter, Gauge, Info, generate_latest, REGISTRY
from typing import Dict


san_blocked_requests = Counter(
    "san_blocked_requests_total",
    "Total requests blocked by the ITCD pipeline",
    ["phase", "reason"],
)

san_allowed_requests = Counter(
    "san_allowed_requests_total",
    "Total requests allowed through the pipeline",
    ["phase"],
)

san_pipeline_duration = Counter(
    "san_pipeline_duration_ms_total",
    "Total pipeline processing time in milliseconds",
    ["phase"],
)

san_hitl_pending = Gauge(
    "san_hitl_pending_requests",
    "Number of pending HITL approval requests",
)

san_kill_switch_active = Gauge(
    "san_kill_switch_active",
    "Whether the kill-switch is active (1) or inactive (0)",
)

san_circuit_breaker_open = Gauge(
    "san_circuit_breaker_open_agents",
    "Number of agents with open circuit breakers",
)

san_anomaly_score = Gauge(
    "san_anomaly_score",
    "Anomaly score for an agent",
    ["agent_id", "agent_name"],
)

san_trust_score = Gauge(
    "san_trust_score",
    "Trust score for an agent",
    ["agent_id", "agent_name"],
)

san_container_count = Gauge(
    "san_container_count",
    "Number of active sandbox containers",
)

san_agent_count = Gauge(
    "san_agent_active_total",
    "Number of active agents",
)

san_vault_connected = Gauge(
    "san_vault_connected",
    "Whether Vault is connected (1) or not (0)",
)

san_info = Info("san_build", "SecureAgentNet build information")


def init_metrics():
    san_info.info({"version": "2.0.0", "pipeline": "ITCD"})


def refresh_metrics():
    """Update all gauge metrics from live system state."""
    try:
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        san_agent_count.set(IdentityRegistry.get_active_count())

        agents = IdentityRegistry.list_agents()
        for agent in agents:
            aid = agent["agent_id"]
            name = agent.get("name", aid)
            san_trust_score.labels(agent_id=aid, agent_name=name).set(
                agent.get("trust_score", 0)
            )
    except Exception:
        pass

    try:
        from src.decide.hitl import get_hitl_gate
        gate = get_hitl_gate()
        san_hitl_pending.set(gate.pending_count)
    except Exception:
        pass

    try:
        from src.track.vault_client import VaultAuditClient
        v = VaultAuditClient()
        san_vault_connected.set(1 if v.client else 0)
    except Exception:
        san_vault_connected.set(0)

    try:
        from src.contain.resource_manager import ContainerResourceManager
        san_container_count.set(ContainerResourceManager.get_running_count())
    except Exception:
        pass


def record_block(phase: str, reason: str):
    san_blocked_requests.labels(phase=phase, reason=reason).inc()


def record_allow(phase: str):
    san_allowed_requests.labels(phase=phase).inc()


def record_duration_ms(phase: str, ms: int):
    san_pipeline_duration.labels(phase=phase).inc(ms)

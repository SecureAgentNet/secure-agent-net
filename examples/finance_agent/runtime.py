"""Commission and connect the simulated payroll agent to the MCP gateway."""
from __future__ import annotations

from secureagentnet.decide.intent_capsule import MandateRegistry
from secureagentnet.identify.capability_profiler import CapabilityProfiler
from secureagentnet.identify.identity_registry import IdentityRegistry

from examples.langchain_email_agent.runtime import (
    connect,
    generate_keypair,
    reset_enforcement_state,
    start_gateway,
)

AGENT_NAME = "secureagentnet-payroll-agent"
GOAL = (
    "Pay each registered employee their approved monthly salary to that employee's "
    "registered payroll account. Never transfer money to external, unlisted, or "
    "attacker-controlled accounts; never change payroll records or disclose secrets."
)


def register_and_commission(public_pem: str) -> str:
    """Create a narrowly scoped identity and durable payroll mandate."""
    IdentityRegistry.initialize()
    existing = IdentityRegistry.get_agent_by_name(AGENT_NAME)
    if existing:
        IdentityRegistry.update_agent(existing["agent_id"], {
            "public_key": public_pem, "status": "active", "description": GOAL})
        agent_id = existing["agent_id"]
    else:
        agent_id = IdentityRegistry.register_agent({
            "name": AGENT_NAME,
            "type": "Finance",
            "created_by": "finance-agent-example",
            "description": GOAL,
            "public_key": public_pem,
            "capabilities": {"read_payroll": True, "transfer_funds": True},
        })["agent_id"]
    for capability in ("read_payroll", "transfer_funds"):
        CapabilityProfiler.add_capability(agent_id, capability)
    MandateRegistry.commission(
        agent_id=agent_id,
        original_goal=GOAL,
        approved_actions=["read_payroll", "transfer_funds"],
        forbidden_actions=["exfiltrate_keys", "delete_database", "change_payroll"],
        user_id="finance-agent-example",
        expires_in_minutes=60,
    )
    reset_enforcement_state(agent_id)
    return agent_id

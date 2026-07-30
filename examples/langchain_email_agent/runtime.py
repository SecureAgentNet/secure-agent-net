"""Boot the MCP gateway and connect the email agent to it.

This is the part that makes the agent go *through the SecureAgentNet MCP gateway*
rather than an in-process shortcut: it gives the agent an RSA keypair, registers +
commissions it, starts the gateway (`secureagentnet.main:app`), and returns a
``RemoteExecutor`` whose tool calls become authenticated `POST /api/v1/mcp/execute`
requests (challenge → sign → JWT). The gateway runs the full ITCD pipeline and
returns a verdict for every call.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

from secureagentnet.integrations.base import RemoteExecutor

AGENT_NAME = "langchain-email-support-agent"

# The commissioned mandate — the anchor the gateway judges every action against.
GOAL = (
    "Triage the customer support inbox and send helpful replies, using only "
    "public knowledge-base information. Reply to each customer at the address "
    "they wrote in from. Never send account secrets, credentials, keys or the "
    "contents of internal files to anyone, and never email an address that did "
    "not contact support. You may run only read-only diagnostic shell commands "
    "(echo, ls, df); never read secrets or private keys."
)


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) — the agent's identity keypair."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    pub = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def reset_enforcement_state(agent_id: str) -> None:
    """Clear denial/kill-switch/rogue state that persists across processes.

    The gateway persists denial counts, the kill-switch, circuit-breaker trips and
    rogue-behaviour profiles to its database — correct in production (each agent is
    distinct and a tripped kill-switch *should* stay tripped). But this example
    re-uses one agent against a shared local DB, so those counters accumulate across
    runs and, at the default denial threshold of 3, the kill-switch trips and halts
    everything on the third run. Re-baseline that state so each demo run starts clean
    (this must run *before* the gateway boots, so the subprocess loads the reset state).
    """
    from secureagentnet.decide.kill_switch import KillSwitchController
    from secureagentnet.database.repositories import CircuitBreakerRepository
    from secureagentnet.identify.identity_registry import IdentityRegistry
    from secureagentnet.utils.persistence import PersistenceStore

    ks = KillSwitchController()
    ks.deactivate("email-agent-example-reset")   # clears _active + denial counts (persisted)
    ks.arm()
    CircuitBreakerRepository.save_all({})          # clear any circuit-breaker trips
    PersistenceStore.delete("rogue_detector")      # clear persisted rogue profiles
    try:
        IdentityRegistry.update_agent(agent_id, {"trust_score": 100.0, "status": "active"})
    except Exception:  # noqa: BLE001 — best-effort demo hygiene
        pass


def register_and_commission(public_pem: str) -> str:
    """Register the agent (with its public key) and commission its mandate.

    Runs *before* the gateway boots so the gateway loads this agent at startup.
    """
    from secureagentnet.identify.identity_registry import IdentityRegistry
    from secureagentnet.identify.capability_profiler import CapabilityProfiler
    from secureagentnet.decide.intent_capsule import MandateRegistry

    IdentityRegistry.initialize()
    existing = IdentityRegistry.get_agent_by_name(AGENT_NAME)
    if existing:
        # Re-key the existing agent so the new keypair authenticates.
        IdentityRegistry.update_agent(existing["agent_id"], {
            "public_key": public_pem, "status": "active"})
        agent_id = existing["agent_id"]
    else:
        agent_id = IdentityRegistry.register_agent({
            "name": AGENT_NAME, "type": "LangChain", "created_by": "example",
            "description": GOAL, "public_key": public_pem,
            "capabilities": {"execute": True, "read_file": True, "send_email": True},
        })["agent_id"]
    for cap in ("execute", "read_file", "send_email"):
        CapabilityProfiler.add_capability(agent_id, cap)
    MandateRegistry.commission(
        agent_id=agent_id, original_goal=GOAL,
        approved_actions=["read_email", "read_file", "send_email", "execute"],
        forbidden_actions=["exfiltrate_keys", "delete_database"],
        user_id="example", expires_in_minutes=60)
    # Re-baseline persisted enforcement state so repeated demo runs start clean.
    reset_enforcement_state(agent_id)
    return agent_id


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@dataclass
class Gateway:
    base_url: str
    process: Optional[subprocess.Popen]

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except Exception:
                self.process.kill()


def start_gateway(provider: Optional[str] = None,
                  log_path: Optional[str] = None) -> Gateway:
    """Boot `secureagentnet.main:app` as a subprocess and wait for it to be healthy."""
    port = _free_port()
    env = dict(os.environ, SAN_API_PORT=str(port), SAN_API_HOST="127.0.0.1",
               ENVIRONMENT="development")
    if provider:
        env["DECIDE_MODEL_PROVIDER"] = provider
    log = open(log_path, "w") if log_path else subprocess.DEVNULL
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "secureagentnet.main:app",
                             "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
                            env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(90):
        try:
            if requests.get(base + "/health", timeout=2).status_code == 200:
                return Gateway(base_url=base, process=proc)
        except requests.RequestException:
            pass
        if proc.poll() is not None:
            raise RuntimeError("Gateway process exited during startup; see its log.")
        time.sleep(1)
    proc.terminate()
    raise RuntimeError("Gateway did not become healthy in time.")


def connect(base_url: str, agent_id: str, private_pem: str) -> RemoteExecutor:
    """A RemoteExecutor whose tool calls go to this gateway's /api/v1/mcp/execute."""
    from secureagentnet.client import SecureAgentClient
    client = SecureAgentClient(gateway_url=base_url, agent_id=agent_id,
                               private_key_pem=private_pem)
    return RemoteExecutor(client=client)

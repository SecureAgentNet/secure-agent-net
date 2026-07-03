"""Deployed-path smoke test against a running containerized gateway.

Unit/integration tests run against the local venv, so they cannot catch packaging
gaps in the built image (e.g. a runtime dependency missing from requirements.txt,
which once made /api/v1/mcp/execute crash with a 500 in the container while every
local test passed). This test drives the real HTTP surface of a running gateway —
operator login, agent registration, Ed25519 challenge/response, and an
authenticated pipeline execution — and auto-skips when no gateway is reachable, so
it is a no-op in environments without the container up.

Point it at a gateway with SAN_GATEWAY_URL (default http://127.0.0.1:5000).
"""
import os

import pytest
import requests

from secureagentnet.utils.crypto import generate_ed25519_keypair, sign_message

BASE = os.environ.get("SAN_GATEWAY_URL", "http://127.0.0.1:5000")
ADMIN_PW = os.environ.get("SAN_ADMIN_PASSWORD", "admin123")


def _gateway_up() -> bool:
    try:
        return requests.get(f"{BASE}/health", timeout=3).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _gateway_up(), reason=f"deployed gateway not reachable at {BASE}")


def test_deployed_auth_and_execute_flow():
    s = requests.Session()

    # 1) operator login
    r = s.post(f"{BASE}/api/v1/auth/operator-login",
               params={"username": "admin", "password": ADMIN_PW}, timeout=10)
    assert r.status_code == 200, r.text
    operator_token = r.json()["access_token"]
    op_headers = {"Authorization": f"Bearer {operator_token}"}

    # 2) register a throwaway agent with a keypair we control
    priv, pub = generate_ed25519_keypair()
    name = f"smoke-{os.getpid()}"
    r = s.post(f"{BASE}/api/v1/security-keys/register",
               json={"agent_name": name, "public_key": pub, "agent_type": "LangChain"},
               headers=op_headers, timeout=10)
    assert r.status_code == 201, r.text
    agent_id = r.json()["agent_id"]

    try:
        # 3) challenge -> sign -> login (exercises Ed25519 challenge/response)
        r = s.post(f"{BASE}/api/v1/auth/challenge", json={"public_key": pub}, timeout=10)
        assert r.status_code == 200, r.text
        challenge = r.json()
        signature = sign_message(priv, challenge["nonce"].encode())
        r = s.post(f"{BASE}/api/v1/auth/login",
                   json={"session_id": challenge["session_id"], "signature": signature}, timeout=10)
        assert r.status_code == 200, r.text
        agent_token = r.json()["access_token"]

        # 4) authenticated execute must REACH the pipeline (HTTP 200, not a 500 import
        #    crash) and return a proper decision. An uncommissioned agent fails closed
        #    downstream of the trust gate — never a crash.
        r = s.post(f"{BASE}/api/v1/mcp/execute",
                   headers={"Authorization": f"Bearer {agent_token}"},
                   json={"action_name": "execute", "target_resource": "shell",
                         "intent_summary": "deployed smoke test", "payload": {"command": "echo hi"}},
                   timeout=40)
        assert r.status_code == 200, r.text
        decision = r.json()
        assert decision["status"] == "blocked"
        assert decision["phase"] == "IDENTIFY"
        assert decision["evaluated_by"] in (
            "CapabilityProfiler", "MandateRegistry", "TrustChainService")
    finally:
        # clean up the throwaway agent so the registry is not polluted
        s.delete(f"{BASE}/api/v1/security-keys/{agent_id}", headers=op_headers, timeout=10)

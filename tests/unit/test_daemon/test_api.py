import pytest
from fastapi.testclient import TestClient

from secureagentnet.daemon.api import create_app
from secureagentnet.daemon.config import DaemonSettings
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.track.log_indexer import LogIndexer


@pytest.fixture
def client(tmp_path, monkeypatch):
    data_dir = tmp_path / "san"
    data_dir.mkdir()
    settings = DaemonSettings(data_dir=data_dir)
    app = create_app(settings=settings)
    IdentityRegistry.initialize()
    LogIndexer.initialize()
    with TestClient(app) as tc:
        yield tc


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_status(client):
    resp = client.get("/v1/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "agents_total" in data


def test_registered_agents_lists_registry(client):
    # An agent that is registered but not a live process must still appear.
    agent = IdentityRegistry.register_agent(
        {"name": "payroll-bot", "type": "LangChain", "capabilities": {"execute": True}})
    resp = client.get("/v1/agents")
    assert resp.status_code == 200
    data = resp.json()
    row = next((a for a in data if a["agent_id"] == agent["agent_id"]), None)
    assert row is not None, "registered agent missing from /v1/agents"
    assert row["name"] == "payroll-bot"
    assert row["framework"] == "LangChain"
    assert row["status"] == "active"
    assert row["live"] is False
    assert row["container"]["status"] == "none"


def test_agent_contracts_are_exposed_from_audit_events(client):
    LogIndexer.index_event({
        "agent_id": "finance-001",
        "phase": "IDENTIFY",
        "event_type": "pipeline_started",
        "severity": "INFO",
        "details": {"security_context": {
            "agent_name": "finance-agent", "project_name": "FinanceOps",
            "framework": "langchain", "role": "payment-review",
            "mandate": "Review approved payments",
            "capabilities": ["read_payroll", "transfer_funds"],
        }},
    })

    resp = client.get("/v1/agent-contracts")

    assert resp.status_code == 200
    assert resp.json()[0]["framework"] == "langchain"


def test_agent_detail_enriched(client):
    from secureagentnet.contain.resource_manager import ContainerResourceManager, get_default_quota
    from secureagentnet.track.log_indexer import LogIndexer
    agent = IdentityRegistry.register_agent(
        {"name": "detail-bot", "type": "CrewAI",
         "capabilities": {"execute": True, "web_search": True, "denied": False}})
    aid = agent["agent_id"]
    ContainerResourceManager.register_container("cont_xyz", aid, get_default_quota())
    LogIndexer.index_event({"agent_id": aid, "phase": "DECIDE",
                            "event_type": "semantic_eval", "summary": "approved", "severity": "INFO"})

    resp = client.get(f"/v1/agents/{aid}")
    assert resp.status_code == 200
    d = resp.json()
    # capabilities = only the granted ones
    assert d["capabilities"] == ["execute", "web_search"]
    # container resources surfaced
    assert d["container"]["container_id"] == "cont_xyz"
    assert d["container"]["memory_limit_mb"] == get_default_quota().memory_limit_mb
    # security profile present and structured
    assert d["security_profile"]["Read-only filesystem"] is True
    assert d["security_profile"]["Capabilities dropped"] == "ALL"
    # timeline events carry a timestamp (DB-stamped) under the "time" key
    assert d["timeline"], "expected at least one timeline event"
    assert d["timeline"][0]["time"]
    assert d["current_phase"] == "DECIDE"


def test_agent_detail_404(client):
    assert client.get("/v1/agents/nonexistent-id").status_code == 404


def test_service_health(client):
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    for svc in ("Database", "Vault", "Ollama LLM", "Docker", "MCP Gateway"):
        assert svc in data
        assert data[svc] in ("online", "offline")


def test_hitl_pending_and_decide(client):
    from secureagentnet.decide.hitl import get_hitl_gate
    gate = get_hitl_gate()
    gate.create_pending_request(
        request_id="req-test-1", agent_id="agent-1", action_name="send_email",
        target_resource="smtp", intent_summary="reply", risk_score=0.6,
        reason="external send vs mandate",
    )
    pending = client.get("/v1/hitl/pending").json()["pending"]
    assert any(r["request_id"] == "req-test-1" for r in pending)

    resp = client.post("/v1/hitl/req-test-1/approve")
    assert resp.status_code == 200
    assert resp.json()["decision"] == "approved"
    assert all(r["request_id"] != "req-test-1"
               for r in client.get("/v1/hitl/pending").json()["pending"])


def test_intercept_blocks_unknown_agent(client):
    resp = client.post("/v1/intercept", json={
        "agent_id": "unknown-agent",
        "action_name": "execute",
        "target_resource": "shell",
        "intent_summary": "Run command",
        "payload": {"command": "ls"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"


def test_intercept_allows_registered_agent_with_mandate(client, monkeypatch):
    agent = IdentityRegistry.register_agent({
        "name": "test-agent",
        "type": "test",
        "capabilities": {"read_file": True},
        "metadata": {},
        "created_by": "test",
    })
    from secureagentnet.decide.intent_capsule import MandateRegistry
    MandateRegistry.commission(
        agent_id=agent["agent_id"],
        original_goal="Read allowed files",
        approved_actions=["read_file"],
        forbidden_actions=[],
        user_id="test",
        expires_in_minutes=60,
    )

    # Mock container provisioner to avoid Docker requirement.
    from secureagentnet.contain.models import ExecutionResult

    class FakeHandle:
        sandbox_id = "sandbox-test"

    # Patch the already-instantiated provisioner on the daemon's pipeline.
    provisioner = client.app.state.daemon_state.pipeline.provisioner
    monkeypatch.setattr(provisioner, "provision_sandbox", lambda *args, **kwargs: FakeHandle())
    monkeypatch.setattr(provisioner, "teardown_sandbox", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        provisioner,
        "execute_in_sandbox",
        lambda *args, **kwargs: ExecutionResult(
            sandbox_id="sandbox-test",
            exit_code=0,
            stdout="ok",
            stderr="",
            execution_time_ms=1,
        ),
    )

    # Mock semantic evaluator to return safe.
    def mock_evaluate(self, request, payload):
        return 0.1, "safe"
    monkeypatch.setattr("secureagentnet.decide.semantic_evaluator.SemanticEvaluator.evaluate", mock_evaluate)

    resp = client.post("/v1/intercept", json={
        "agent_id": agent["agent_id"],
        "action_name": "read_file",
        "target_resource": "/tmp/allowed.txt",
        "intent_summary": "Read allowed file",
        "payload": {"command": "cat /tmp/allowed.txt"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"

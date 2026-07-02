import pytest
import json
from fastapi.testclient import TestClient as FastAPITestClient
from unittest.mock import patch, MagicMock

from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.identify.capability_profiler import CapabilityProfiler
from secureagentnet.contain.resource_manager import ContainerResourceManager
from secureagentnet.decide.intent_capsule import IntentCapsuleManager


@pytest.fixture(autouse=True)
def reset_state():
    IdentityRegistry._agents = {}
    IdentityRegistry._initialized = True
    LogIndexer._events = []
    ContainerResourceManager._containers = {}
    CapabilityProfiler._mock_db = {
        "agent-007": ["read_file", "execute_sql", "search_web"],
        "agent-rogue": ["search_web"],
    }
    IntentCapsuleManager._capsules = {}

    IdentityRegistry.register_agent({
        "name": "admin-agent",
        "type": "Custom",
        "description": "Built-in admin agent for system management",
        "public_key": "",
        "capabilities": {"level": "admin", "actions": ["*"]},
        "metadata": {"system": True},
        "created_by": "system",
    })
    yield


@pytest.fixture
def fastapi_client():
    from secureagentnet.main import app
    return FastAPITestClient(app)


@pytest.fixture
def flask_client():
    from secureagentnet.interfaces.web_dashboard.app import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["RATELIMIT_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client


class TestHealthAndVersion:

    def test_health_endpoint(self, fastapi_client):
        response = fastapi_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "SecureAgentNet Gateway"
        assert data["version"] == "2.0.0"
        assert "agents_registered" in data
        assert "agents_active" in data
        assert data["agents_registered"] >= 1

    def test_version_endpoint(self, fastapi_client):
        response = fastapi_client.get("/api/version")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "2.0.0"
        assert data["name"] == "SecureAgentNet"
        assert "phases" in data
        assert "IDENTIFY" in data["phases"]
        assert "TRACK" in data["phases"]
        assert "CONTAIN" in data["phases"]
        assert "DECIDE" in data["phases"]


class TestAgentAPI:

    def test_register_agent_api(self, flask_client):
        payload = {
            "name": "api-test-agent",
            "type": "LangChain",
            "description": "Agent registered via API test",
            "public_key": "pub-key-api-001",
            "capabilities": {"actions": ["search_web", "read_file"]},
            "metadata": {"framework": "langchain", "version": "0.1.0"},
            "created_by": "api-test",
        }
        response = flask_client.post(
            "/api/agents",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["name"] == "api-test-agent"
        assert data["type"] == "LangChain"
        assert data["status"] == "active"
        assert data["trust_score"] == 50.0
        assert "agent_id" in data

        registered = IdentityRegistry.get_agent(data["agent_id"])
        assert registered is not None
        assert registered["public_key"] == "pub-key-api-001"

    def test_register_agent_api_invalid_data(self, flask_client):
        response = flask_client.post(
            "/api/agents",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_get_agent_api(self, flask_client):
        agent = IdentityRegistry.register_agent({
            "name": "get-test-agent",
            "type": "Custom",
            "description": "Agent for GET test",
            "public_key": "get-key-001",
            "created_by": "pytest",
        })
        agent_id = agent["agent_id"]

        response = flask_client.get(f"/api/agents/{agent_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["name"] == "get-test-agent"
        assert data["agent_id"] == agent_id

    def test_get_agent_api_not_found(self, flask_client):
        response = flask_client.get("/api/agents/non-existent-id")
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_list_agents_api(self, flask_client):
        IdentityRegistry.register_agent({
            "name": "list-agent-1", "type": "LangChain",
            "public_key": "lk1", "created_by": "pytest",
        })
        IdentityRegistry.register_agent({
            "name": "list-agent-2", "type": "CrewAI",
            "public_key": "lk2", "created_by": "pytest",
        })

        response = flask_client.get("/api/agents")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) >= 3
        names = [a["name"] for a in data]
        assert "list-agent-1" in names
        assert "list-agent-2" in names

    def test_update_agent_api(self, flask_client):
        agent = IdentityRegistry.register_agent({
            "name": "update-test-agent",
            "type": "Custom",
            "public_key": "update-key",
            "created_by": "pytest",
        })
        agent_id = agent["agent_id"]

        response = flask_client.put(
            f"/api/agents/{agent_id}",
            data=json.dumps({"description": "Updated description", "type": "AutoGen"}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["description"] == "Updated description"
        assert data["type"] == "AutoGen"

    def test_update_agent_api_not_found(self, flask_client):
        response = flask_client.put(
            "/api/agents/non-existent",
            data=json.dumps({"description": "test"}),
            content_type="application/json",
        )
        assert response.status_code == 404

    def test_delete_agent_api(self, flask_client):
        agent = IdentityRegistry.register_agent({
            "name": "delete-test-agent",
            "type": "Custom",
            "public_key": "delete-key",
            "created_by": "pytest",
        })
        agent_id = agent["agent_id"]

        response = flask_client.delete(f"/api/agents/{agent_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        deleted = IdentityRegistry.get_agent(agent_id)
        assert deleted["status"] == "revoked"

    def test_delete_agent_api_not_found(self, flask_client):
        response = flask_client.delete("/api/agents/non-existent")
        assert response.status_code == 404


class TestPipelineExecuteAPI:

    def test_pipeline_execute_api(self, flask_client, monkeypatch):
        agent = IdentityRegistry.register_agent({
            "name": "pipeline-agent",
            "type": "Custom",
            "public_key": "pipe-key",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "pytest",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")

        import secureagentnet.core.pipeline as pipeline_module
        from secureagentnet.contain.models import ExecutionResult

        from types import SimpleNamespace

        def mock_provision(self, request, config=None):
            return SimpleNamespace(sandbox_id="sandbox-api-test")

        def mock_execute(self, handle):
            return ExecutionResult(
                sandbox_id="sandbox-api-test",
                exit_code=0,
                stdout="pipeline executed",
                stderr="",
                execution_time_ms=50,
                was_killed=False,
            )

        def mock_teardown(self, handle, executed=True):
            return None

        monkeypatch.setattr(
            pipeline_module.ContainerProvisioner, "provision_sandbox", mock_provision
        )
        monkeypatch.setattr(
            pipeline_module.ContainerProvisioner, "execute_in_sandbox", mock_execute
        )
        monkeypatch.setattr(
            pipeline_module.ContainerProvisioner, "teardown_sandbox", mock_teardown
        )

        import secureagentnet.track.vault_client as vault_module
        monkeypatch.setattr(
            vault_module.VaultAuditClient, "secure_log", lambda self, x: "vault-receipt-api-001"
        )

        from secureagentnet.decide import SemanticEvaluator
        monkeypatch.setattr(
            SemanticEvaluator, "evaluate",
            lambda self, req, redacted: (0.1, "Benign API test")
        )

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/test.txt",
                "intent": "Read configuration file",
                "command": "cat /tmp/test.txt",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] in ("success",)
        if data["status"] == "success":
            assert "correlation_id" in data
            assert "vault_receipt" in data

    def test_pipeline_execute_api_invalid(self, flask_client):
        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert response.status_code == 400


class TestForensicSearchAPI:

    def test_forensic_search_api(self, flask_client):
        LogIndexer.index_event({
            "timestamp": "2025-01-01T00:00:00Z",
            "agent_id": "test-agent-001",
            "event_type": "pipeline_started",
            "phase": "IDENTIFY",
            "severity": "INFO",
            "summary": "Pipeline started for agent test-agent-001",
            "details": {},
            "correlation_id": "corr-test-001",
        })
        LogIndexer.index_event({
            "timestamp": "2025-01-01T00:00:01Z",
            "agent_id": "test-agent-001",
            "event_type": "decision_denied",
            "phase": "DECIDE",
            "severity": "WARNING",
            "summary": "Decision denied - prompt injection detected in request",
            "details": {"reason": "Prompt injection detected"},
            "correlation_id": "corr-test-001",
        })

        response = flask_client.post(
            "/api/forensics/search",
            data=json.dumps({"query": "injection"}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "results" in data
        assert "total" in data
        assert data["total"] > 0

    def test_forensic_search_api_empty_query(self, flask_client):
        response = flask_client.post(
            "/api/forensics/search",
            data=json.dumps({"query": ""}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["total"] == 0


class TestKillSwitchAPI:

    def test_kill_switch_activate_api(self, flask_client):
        for _ in range(3):
            flask_client.post("/api/security/kill-switch/activate")
        response = flask_client.post("/api/security/kill-switch/activate")
        assert response.status_code == 200
        data = response.get_json()
        assert data["active"] is True

    def test_kill_switch_reset_api(self, flask_client):
        for _ in range(3):
            flask_client.post("/api/security/kill-switch/activate")

        response = flask_client.post("/api/security/kill-switch/reset")
        assert response.status_code == 200
        data = response.get_json()
        assert data["active"] is False
        assert data["armed"] is True

    def test_kill_switch_status_via_activate(self, flask_client):
        for _ in range(3):
            flask_client.post("/api/security/kill-switch/activate")
        response = flask_client.post("/api/security/kill-switch/activate")
        data = response.get_json()
        assert "trigger_count" in data
        assert data["trigger_count"] >= 1
        assert "last_triggered_at" in data


class TestMetricsAPI:

    def test_metrics_summary_api(self, flask_client):
        IdentityRegistry.register_agent({
            "name": "metrics-agent", "type": "Custom",
            "public_key": "metrics-key", "created_by": "pytest",
        })

        LogIndexer.index_event({
            "timestamp": "2025-01-01T00:00:00Z",
            "agent_id": "metrics-agent",
            "event_type": "pipeline_started",
            "phase": "IDENTIFY",
            "severity": "INFO",
            "details": {},
            "correlation_id": "corr-metrics",
        })

        response = flask_client.get("/api/metrics/summary")
        assert response.status_code == 200
        data = response.get_json()
        assert "total_events" in data
        assert "active_agents" in data
        assert "total_agents" in data
        assert "phases" in data
        assert "severity_distribution" in data
        assert data["total_events"] >= 1


class TestDashboardEndpoints:

    def test_dashboard_login_page(self, flask_client):
        response = flask_client.get("/login")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")

    def test_dashboard_login_post_success(self, flask_client):
        response = flask_client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        assert response.status_code in (302, 200)

    def test_dashboard_login_post_failure(self, flask_client):
        response = flask_client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
        )
        assert response.status_code == 200

    def test_dashboard_health(self, flask_client):
        response = flask_client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"


class TestAuthRouter:

    def test_challenge_endpoint(self, fastapi_client):
        payload = {"public_key": "test-key-for-challenge"}
        response = fastapi_client.post("/api/v1/auth/challenge", json=payload)
        assert response.status_code in (200, 401, 422)

    def test_login_endpoint(self, fastapi_client):
        payload = {
            "session_id": "test-session",
            "signature": "test-signature",
            "public_key": "test-key",
        }
        response = fastapi_client.post("/api/v1/auth/login", json=payload)
        assert response.status_code in (200, 401, 422)

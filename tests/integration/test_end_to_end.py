import pytest
import json
import asyncio
from unittest.mock import patch

from src.identify.identity_registry import IdentityRegistry
from src.identify.capability_profiler import CapabilityProfiler
from src.track.log_indexer import LogIndexer
from src.track.forensic_query import ForensicQueryEngine
from src.contain.resource_manager import ContainerResourceManager
from src.decide.intent_capsule import IntentCapsuleManager
from src.decide.kill_switch import KillSwitchController
from src.core.constants import AgentStatus
from src.contain.models import ExecutionResult


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
        "name": "admin-agent", "type": "Custom",
        "description": "System admin",
        "public_key": "",
        "capabilities": {"level": "admin", "actions": ["*"]},
        "metadata": {"system": True},
        "created_by": "system",
    })
    yield


@pytest.fixture
def flask_client():
    from src.interfaces.web_dashboard.app import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["RATELIMIT_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def reset_kill_switch():
    from src.interfaces.web_dashboard.app import pipeline as dashboard_pipeline
    dashboard_pipeline.kill_switch.deactivate("test-autoreset")
    yield


@pytest.fixture
def mock_sandbox(monkeypatch):
    from src.core import pipeline as pipeline_module

    from types import SimpleNamespace

    def fake_provision(self, request, config=None):
        return SimpleNamespace(sandbox_id="sandbox-e2e")

    def fake_execute(self, handle):
        return ExecutionResult(
            sandbox_id="sandbox-e2e",
            exit_code=0,
            stdout="e2e execution success",
            stderr="",
            execution_time_ms=30,
            was_killed=False,
        )

    def fake_teardown(self, handle, executed=True):
        return None

    monkeypatch.setattr(
        pipeline_module.ContainerProvisioner, "provision_sandbox", fake_provision
    )
    monkeypatch.setattr(
        pipeline_module.ContainerProvisioner, "execute_in_sandbox", fake_execute
    )
    monkeypatch.setattr(
        pipeline_module.ContainerProvisioner, "teardown_sandbox", fake_teardown
    )

    from src.track import vault_client as vault_module
    monkeypatch.setattr(
        vault_module.VaultAuditClient, "secure_log", lambda self, x: "vault-receipt-e2e-001"
    )

    from src.decide import SemanticEvaluator
    monkeypatch.setattr(
        SemanticEvaluator, "evaluate",
        lambda self, req, redacted: (0.1, "Benign e2e request")
    )


class TestEndToEndWorkflow:

    def test_register_agent_through_api(self, flask_client, mock_sandbox):
        payload = {
            "name": "e2e-production-agent",
            "type": "CrewAI",
            "description": "End-to-end production agent for automated tasks",
            "public_key": "e2e-pub-key-001",
            "capabilities": {
                "actions": ["read_file", "search_web", "execute_sql"],
                "level": "standard",
            },
            "metadata": {
                "framework": "crewai",
                "team": "data-processing",
                "environment": "staging",
            },
            "created_by": "admin",
        }

        response = flask_client.post(
            "/api/agents",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert response.status_code == 201
        agent_data = response.get_json()
        agent_id = agent_data["agent_id"]

        assert agent_data["name"] == "e2e-production-agent"
        assert agent_data["status"] == AgentStatus.ACTIVE.value
        assert agent_data["trust_score"] == 50.0
        assert agent_data["created_by"] == "admin"

        get_response = flask_client.get(f"/api/agents/{agent_id}")
        assert get_response.status_code == 200
        assert get_response.get_json()["agent_id"] == agent_id

        list_response = flask_client.get("/api/agents")
        assert list_response.status_code == 200
        agent_ids = [a["agent_id"] for a in list_response.get_json()]
        assert agent_id in agent_ids

        CapabilityProfiler.add_capability(agent_id, "read_file")
        CapabilityProfiler.add_capability(agent_id, "search_web")
        CapabilityProfiler.add_capability(agent_id, "execute_sql")

        return agent_id

    def test_submit_request_through_pipeline(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "pipeline-e2e-agent",
            "type": "LangChain",
            "public_key": "e2e-pipe-key",
            "capabilities": {"actions": ["read_file", "search_web"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/config.yaml",
                "intent": "Read application configuration for deployment verification",
                "command": "cat /tmp/config.yaml",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert data["data"]["exit_code"] == 0
        assert data["data"]["stdout"] == "e2e execution success"

        agent_record = IdentityRegistry.get_agent(agent_id)
        assert agent_record["trust_score"] > 50.0

        events = LogIndexer.query_by_agent(agent_id)
        assert len(events) >= 5

        return agent_id, data["correlation_id"]

    def test_submit_request_blocked_by_capability(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "restricted-e2e-agent",
            "type": "Custom",
            "public_key": "e2e-restricted-key",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "execute_sql",
                "resource": "production_users",
                "intent": "Drop all user sessions from database",
                "command": "psql -c 'DELETE FROM sessions'",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "blocked"
        assert data["evaluated_by"] == "CapabilityProfiler"
        assert data["phase"] == "IDENTIFY"

    def test_submit_request_blocked_by_rule_filter(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "malicious-e2e-agent",
            "type": "Custom",
            "public_key": "e2e-mal-key",
            "capabilities": {"actions": ["delete_database", "read_file"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "delete_database")

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "delete_database",
                "resource": "production_db",
                "intent": "Remove outdated test data",
                "command": "DROP DATABASE production",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "blocked"
        assert data["evaluated_by"] == "RuleFilter"

    def test_submit_request_with_dangerous_path(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "path-e2e-agent",
            "type": "Custom",
            "public_key": "e2e-path-key",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/etc/shadow",
                "intent": "Read authentication database",
                "command": "cat /etc/shadow",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "blocked"
        assert "shadow" in data["reason"].lower()

    def test_register_and_execute_full_workflow(self, flask_client, mock_sandbox):
        agent_id = self.test_register_agent_through_api(flask_client, mock_sandbox)

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/deploy.yaml",
                "intent": "Verify deployment configuration before applying changes",
                "command": "cat /tmp/deploy.yaml",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"

        forensic_response = flask_client.post(
            "/api/forensics/search",
            data=json.dumps({"query": "pipeline_started"}),
            content_type="application/json",
        )
        assert forensic_response.status_code == 200
        forensic_data = forensic_response.get_json()
        assert forensic_data["total"] > 0

        return agent_id

    def test_query_forensics(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "forensic-e2e-agent",
            "type": "LangChain",
            "public_key": "e2e-forensic-key",
            "capabilities": {"actions": ["read_file", "search_web"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")
        CapabilityProfiler.add_capability(agent_id, "search_web")

        flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/app.log",
                "intent": "Read application log for error analysis",
                "command": "cat /tmp/app.log",
            }),
            content_type="application/json",
        )

        flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "search_web",
                "resource": "https://api.example.com",
                "intent": "Fetch external API data for report",
                "command": "curl https://api.example.com/data",
            }),
            content_type="application/json",
        )

        agent_response = flask_client.get(f"/api/agents/{agent_id}")
        assert agent_response.status_code == 200

        search_response = flask_client.post(
            "/api/forensics/search",
            data=json.dumps({"query": "pipeline_started"}),
            content_type="application/json",
        )
        assert search_response.status_code == 200
        search_data = search_response.get_json()
        assert search_data["total"] > 0

        summary_response = flask_client.get("/api/metrics/summary")
        assert summary_response.status_code == 200
        summary = summary_response.get_json()
        assert summary["total_events"] >= 10
        assert summary["active_agents"] >= 1

    def test_security_dashboard_endpoints(self, flask_client):
        health_response = flask_client.get("/health")
        assert health_response.status_code == 200
        assert health_response.get_json()["status"] == "healthy"

        login_response = flask_client.get("/login")
        assert login_response.status_code == 200

        login_post = flask_client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        assert login_post.status_code in (302, 200)

        summary_response = flask_client.get("/api/metrics/summary")
        assert summary_response.status_code == 200

    def test_kill_switch_workflow(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "ks-e2e-agent",
            "type": "Custom",
            "public_key": "e2e-ks-key",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")

        for _ in range(3):
            flask_client.post("/api/security/kill-switch/activate")

        activate_response = flask_client.post("/api/security/kill-switch/activate")
        assert activate_response.status_code == 200
        assert activate_response.get_json()["active"] is True

        response = flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/test.txt",
                "intent": "Read test file",
                "command": "cat /tmp/test.txt",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "blocked"
        assert "kill" in data["reason"].lower()

        reset_response = flask_client.post("/api/security/kill-switch/reset")
        assert reset_response.status_code == 200
        assert reset_response.get_json()["active"] is False

        from src.interfaces.web_dashboard.app import pipeline as dashboard_pipeline
        dashboard_pipeline.kill_switch.deactivate("test-cleanup")
        dashboard_pipeline.kill_switch.arm()

    def test_agent_lifecycle_full(self, flask_client):
        register_response = flask_client.post(
            "/api/agents",
            data=json.dumps({
                "name": "lifecycle-agent",
                "type": "Custom",
                "public_key": "lifecycle-key",
                "created_by": "admin",
            }),
            content_type="application/json",
        )
        assert register_response.status_code == 201
        agent_id = register_response.get_json()["agent_id"]

        update_response = flask_client.put(
            f"/api/agents/{agent_id}",
            data=json.dumps({"description": "Updated lifecycle agent"}),
            content_type="application/json",
        )
        assert update_response.status_code == 200

        get_response = flask_client.get(f"/api/agents/{agent_id}")
        assert get_response.status_code == 200

        delete_response = flask_client.delete(f"/api/agents/{agent_id}")
        assert delete_response.status_code == 200

        deleted_agent = IdentityRegistry.get_agent(agent_id)
        assert deleted_agent["status"] == AgentStatus.REVOKED.value

    def test_end_to_end_with_forensic_investigation(self, flask_client, mock_sandbox):
        agent = IdentityRegistry.register_agent({
            "name": "investigate-e2e-agent",
            "type": "AutoGen",
            "public_key": "e2e-invest-key",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "admin",
        })
        agent_id = agent["agent_id"]
        CapabilityProfiler.add_capability(agent_id, "read_file")

        flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/config.yaml",
                "intent": "Read configuration",
                "command": "cat /tmp/config.yaml",
            }),
            content_type="application/json",
        )

        flask_client.post(
            "/api/pipeline/execute",
            data=json.dumps({
                "agent_id": agent_id,
                "action": "read_file",
                "resource": "/tmp/secrets.env",
                "intent": "Read environment secrets",
                "command": "cat /tmp/secrets.env",
            }),
            content_type="application/json",
        )

        forensic_response = flask_client.post(
            "/api/forensics/search",
            data=json.dumps({"query": "container_executed"}),
            content_type="application/json",
        )
        assert forensic_response.status_code == 200
        forensic_data = forensic_response.get_json()
        assert forensic_data["total"] > 0

    def test_concurrent_agent_requests(self, flask_client, mock_sandbox):
        agents = []
        for i in range(3):
            agent = IdentityRegistry.register_agent({
                "name": f"concurrent-agent-{i}",
                "type": "Custom",
                "public_key": f"concurrent-key-{i}",
                "capabilities": {"actions": ["read_file"]},
                "created_by": "admin",
            })
            agent_id = agent["agent_id"]
            CapabilityProfiler.add_capability(agent_id, "read_file")
            agents.append(agent_id)

        responses = []
        for aid in agents:
            resp = flask_client.post(
                "/api/pipeline/execute",
                data=json.dumps({
                    "agent_id": aid,
                    "action": "read_file",
                    "resource": "/tmp/data.txt",
                    "intent": f"Data read by {aid}",
                    "command": "cat /tmp/data.txt",
                }),
                content_type="application/json",
            )
            responses.append(resp)

        for resp in responses:
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["status"] == "success"

        for agent_id in agents:
            events = LogIndexer.query_by_agent(agent_id)
            assert len(events) >= 5

import pytest
import json
from unittest.mock import patch, MagicMock

from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.decide.hitl import get_hitl_gate, HITLDecision
from secureagentnet.identify.rogue_detector import RogueDetector, get_rogue_detector


@pytest.fixture(autouse=True)
def reset_state():
    IdentityRegistry._agents = {}
    IdentityRegistry._initialized = True
    
    # Reset HITL gate
    gate = get_hitl_gate()
    gate._pending_requests.clear()
    gate._callbacks.clear()
    
    # Reset Rogue Detector
    detector = get_rogue_detector()
    detector._profiles.clear()
    detector._transition_graph._transitions.clear()
    detector._transition_graph._agent_histories.clear()
    
    yield


@pytest.fixture
def fastapi_client():
    from fastapi.testclient import TestClient
    from secureagentnet.main import app
    return TestClient(app)


class TestHITLRoutes:
    def test_list_pending_requests_empty(self, fastapi_client):
        response = fastapi_client.get("/api/v1/hitl/pending")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["requests"] == []

    def test_approve_request(self, fastapi_client):
        gate = get_hitl_gate()
        rid = gate.create_pending_request(
            "req-123", "agent-1", "execute_sql",
            "users", "select users", 0.6, "risk"
        )
        
        response = fastapi_client.post(f"/api/v1/hitl/approve/{rid}")
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == rid
        assert data["decision"] == HITLDecision.APPROVED.value
        assert data["request"]["status"] == "approved"

    def test_deny_request(self, fastapi_client):
        gate = get_hitl_gate()
        rid = gate.create_pending_request(
            "req-456", "agent-1", "write_file",
            "file", "write file", 0.6, "risk"
        )
        
        response = fastapi_client.post(f"/api/v1/hitl/deny/{rid}")
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == rid
        assert data["decision"] == HITLDecision.DENIED.value
        assert data["request"]["status"] == "denied"

    def test_approve_nonexistent_request(self, fastapi_client):
        response = fastapi_client.post("/api/v1/hitl/approve/nonexistent")
        assert response.status_code == 404

    def test_hitl_summary(self, fastapi_client):
        gate = get_hitl_gate()
        gate.create_pending_request("r1", "a", "x", "y", "z", 0.5, "w")
        
        response = fastapi_client.get("/api/v1/hitl/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["pending_count"] == 1


class TestBehaviorRoutes:
    def test_get_agent_behavior_graph_not_found(self, fastapi_client):
        response = fastapi_client.get("/api/v1/behavior/agents/nonexistent/graph")
        assert response.status_code == 404

    def test_get_agent_behavior_graph_success(self, fastapi_client):
        agent = IdentityRegistry.register_agent({
            "name": "behavior-agent",
            "type": "Custom",
            "description": "test",
            "public_key": "pub",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "test",
        })
        agent_id = agent["agent_id"]
        
        detector = get_rogue_detector()
        detector.record_request(agent_id, "read_file", "file.txt")
        
        response = fastapi_client.get(f"/api/v1/behavior/agents/{agent_id}/graph")
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == agent_id
        assert data["agent_name"] == "behavior-agent"
        assert data["total_requests"] == 1
        assert "read_file" in data["recent_history"]

    def test_get_behavior_summary(self, fastapi_client):
        agent = IdentityRegistry.register_agent({
            "name": "summary-agent",
            "type": "Custom",
            "description": "test",
            "public_key": "pub",
            "capabilities": {"actions": ["read_file"]},
            "created_by": "test",
        })
        agent_id = agent["agent_id"]
        
        detector = get_rogue_detector()
        detector.record_request(agent_id, "read_file", "file.txt")
        
        response = fastapi_client.get("/api/v1/behavior/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["agents_tracked"] >= 1
        assert any(a["agent_id"] == agent_id for a in data["agents"])

import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.utils.crypto import create_access_token
from src.core.config import get_settings


client = TestClient(app)


class TestMCPGateway:
    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_version_endpoint(self):
        resp = client.get("/api/version")
        assert resp.status_code == 200
        assert resp.json()["version"] == "2.0.0"

    def test_challenge_invalid_public_key(self):
        resp = client.post("/api/v1/auth/challenge", json={"public_key": "invalid-key"})
        assert resp.status_code == 401
        assert "Agent identity not found" in resp.json()["detail"]

    def test_challenge_missing_public_key(self):
        resp = client.post("/api/v1/auth/challenge", json={})
        assert resp.status_code == 422

    # --- Protected MCP routes ---

    def test_list_tools_no_auth(self):
        resp = client.get("/api/v1/mcp/tools")
        assert resp.status_code == 401

    def test_list_tools_invalid_token(self):
        resp = client.get(
            "/api/v1/mcp/tools",
            headers={"Authorization": "Bearer invalidtoken"},
        )
        assert resp.status_code == 401

    def test_list_tools_expired_token(self, monkeypatch):
        settings = get_settings()
        # Create a token that's already expired
        from datetime import timedelta
        token = create_access_token(
            {"sub": "nonexistent"},
            settings.secret_key,
            settings.agent_jwt_algorithm,
            expires_delta=timedelta(seconds=-1),
        )
        resp = client.get(
            "/api/v1/mcp/tools",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_list_tools_valid_token_no_agent(self, monkeypatch):
        settings = get_settings()
        token = create_access_token(
            {"sub": "no-such-agent"},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.get(
            "/api/v1/mcp/tools",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    def test_list_tools_valid_token_with_agent(self, monkeypatch):
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "mcp-test-agent",
            "type": "Custom",
            "description": "MCP test agent",
            "public_key": "",
            "capabilities": {},
            "metadata": {},
            "created_by": "test",
        })
        settings = get_settings()
        token = create_access_token(
            {"sub": agent["agent_id"]},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.get(
            "/api/v1/mcp/tools",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == agent["agent_id"]
        assert "tools" in data
        assert data["count"] > 0

    def test_get_agent_info(self, monkeypatch):
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "info-test-agent",
            "type": "LangChain",
            "description": "test",
            "public_key": "",
            "capabilities": {"read": True},
            "metadata": {},
            "created_by": "test",
        })
        settings = get_settings()
        token = create_access_token(
            {"sub": agent["agent_id"]},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.get(
            "/api/v1/mcp/agent",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == agent["agent_id"]
        assert data["name"] == "info-test-agent"
        assert data["status"] == "active"

    def test_execute_tool_no_auth(self):
        resp = client.post("/api/v1/mcp/execute", json={"action_name": "test"})
        assert resp.status_code == 401

    def test_execute_tool_with_auth(self, monkeypatch):
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "exec-test-agent",
            "type": "Custom",
            "description": "test",
            "public_key": "",
            "capabilities": {"execute": True},
            "metadata": {},
            "created_by": "test",
        })
        settings = get_settings()
        token = create_access_token(
            {"sub": agent["agent_id"]},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.post(
            "/api/v1/mcp/execute",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "action_name": "test",
                "target_resource": "shell",
                "intent_summary": "testing",
                "payload": {"command": "echo hello"},
            },
        )
        assert resp.status_code == 200

    def test_heartbeat(self, monkeypatch):
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "hb-test-agent",
            "type": "Custom",
            "description": "test",
            "public_key": "",
            "capabilities": {},
            "metadata": {},
            "created_by": "test",
        })
        settings = get_settings()
        token = create_access_token(
            {"sub": agent["agent_id"]},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.post(
            "/api/v1/mcp/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        updated = IdentityRegistry.get_agent(agent["agent_id"])
        assert updated.get("last_seen") is not None

    def test_heartbeat_no_auth(self):
        resp = client.post("/api/v1/mcp/heartbeat")
        assert resp.status_code == 401

    def test_capabilities(self, monkeypatch):
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "cap-test-agent",
            "type": "CrewAI",
            "description": "test",
            "public_key": "",
            "capabilities": {"execute": True, "read_file": True},
            "metadata": {},
            "created_by": "test",
        })
        settings = get_settings()
        token = create_access_token(
            {"sub": agent["agent_id"]},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.get(
            "/api/v1/mcp/capabilities",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == agent["agent_id"]
        assert data["capabilities"]["execute"] is True
        assert data["capabilities"]["read_file"] is True
        assert data["count"] == 2

    def test_capabilities_no_auth(self):
        resp = client.get("/api/v1/mcp/capabilities")
        assert resp.status_code == 401

    def test_auth_refresh_valid_token(self, monkeypatch):
        from src.identify.identity_registry import IdentityRegistry
        IdentityRegistry.initialize()
        agent = IdentityRegistry.register_agent({
            "name": "refresh-test-agent",
            "type": "Custom",
            "description": "test",
            "public_key": "",
            "capabilities": {},
            "metadata": {},
            "created_by": "test",
        })
        settings = get_settings()
        token = create_access_token(
            {"sub": agent["agent_id"]},
            settings.secret_key,
            settings.agent_jwt_algorithm,
        )
        resp = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "bearer"
        assert data["access_token"] != token

    def test_auth_refresh_no_token(self):
        resp = client.post("/api/v1/auth/refresh")
        assert resp.status_code == 401

    def test_auth_refresh_invalid_token(self):
        resp = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": "Bearer fake.token.here"},
        )
        assert resp.status_code == 401

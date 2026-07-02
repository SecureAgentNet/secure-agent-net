import os
import secrets
import pytest

os.environ["SAN_TESTING"] = "1"
os.environ["ENVIRONMENT"] = "development"


@pytest.fixture
def client(mock_settings, reset_identity_registry, reset_log_indexer, reset_persistence, tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    from secureagentnet.database.connection import dispose_engine, init_database
    from secureagentnet.core.config import get_settings
    dispose_engine()
    get_settings.cache_clear()
    init_database()
    from secureagentnet.main import app
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


class TestOperatorLogin:
    def test_login_invalid_returns_401(self, client):
        res = client.post("/api/v1/auth/operator-login", params={"username": "nobody", "password": "wrong"})
        assert res.status_code == 401

    def test_login_success_returns_token(self, client):
        res = client.post("/api/v1/auth/operator-login", params={"username": "admin", "password": "admin123"})
        assert res.status_code == 200
        body = res.json()
        assert body["access_token"]
        assert body["user"]["role"] == "admin"


class TestMetricsSummary:
    def test_metrics_summary(self, client):
        res = client.get("/api/metrics/summary")
        assert res.status_code == 200
        data = res.json()
        assert "agents_registered" in data


class TestForensicsSearch:
    def test_forensics_search(self, client):
        res = client.get("/api/forensics/search")
        assert res.status_code == 200
        assert isinstance(res.json(), list)


class TestTeamRoutes:
    def test_list_team(self, client):
        res = client.get("/api/v1/team")
        assert res.status_code == 200
        assert isinstance(res.json(), list)


class TestKeyRoutes:
    def test_list_keys(self, client):
        res = client.get("/api/v1/security-keys")
        assert res.status_code == 200

    def test_register_key(self, client):
        key = secrets.token_hex(32)
        name = f"key-{secrets.token_hex(4)}"
        res = client.post("/api/v1/security-keys/register", json={
            "agent_name": name, "public_key": key, "agent_type": "Test",
        })
        assert res.status_code == 201
        assert res.json()["status"] == "active"

    def test_register_duplicate_fails(self, client):
        key = secrets.token_hex(32)
        name = f"dup-key-{secrets.token_hex(4)}"
        client.post("/api/v1/security-keys/register", json={
            "agent_name": name, "public_key": key, "agent_type": "Test",
        })
        res = client.post("/api/v1/security-keys/register", json={
            "agent_name": name, "public_key": key, "agent_type": "Test",
        })
        assert res.status_code == 409


class TestConfigRoutes:
    def test_get_config(self, client):
        res = client.get("/api/v1/itcd/config")
        assert res.status_code == 200
        data = res.json()
        assert "policies" in data

    def test_update_sandbox(self, client):
        res = client.put("/api/v1/itcd/config/sandbox", json={
            "cpu_limit": "2.0", "memory_limit_mb": 1024,
        })
        assert res.status_code == 200
        assert res.json()["cpu_limit"] == "2.0"

    def test_add_policy(self, client):
        res = client.put("/api/v1/itcd/config/policies", json={
            "name": "test-policy",
            "action_type": "block",
            "conditions": {"path": "/etc/passwd"},
            "priority": 10,
        })
        assert res.status_code == 201
        assert res.json()["name"] == "test-policy"


class TestReportRoutes:
    def test_list_reports(self, client):
        res = client.get("/api/v1/reports")
        assert res.status_code == 200

    def test_threats(self, client):
        res = client.get("/api/v1/reports/threats")
        assert res.status_code == 200

    def test_thread_crud(self, client):
        res = client.post("/api/v1/reports/rpt-0000/thread", json={
            "report_id": "rpt-0000", "author": "analyst", "content": "msg",
        })
        assert res.status_code == 201
        thread = client.get("/api/v1/reports/rpt-0000/thread")
        assert thread.status_code == 200


class TestDashboardRoutes:
    def test_list_agents(self, client):
        res = client.get("/api/v1/agents")
        assert res.status_code == 200
        data = res.json()
        assert "total" in data and "agents" in data
        assert isinstance(data["agents"], list)

    def test_security_status(self, client):
        res = client.get("/api/v1/security/status")
        assert res.status_code == 200
        data = res.json()
        assert "kill_switch" in data
        assert "active" in data["kill_switch"]
        assert "agents_total" in data

    def test_kill_switch_activate_then_deactivate(self, client):
        act = client.post("/api/v1/security/kill-switch/activate")
        assert act.status_code == 200
        assert act.json()["kill_switch"]["active"] is True

        deact = client.post("/api/v1/security/kill-switch/deactivate")
        assert deact.status_code == 200
        assert deact.json()["kill_switch"]["active"] is False

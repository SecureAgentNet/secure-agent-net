"""Phase 3.6 — dashboard data routes: overview, endpoints, detail, event search."""
import httpx
import pytest


@pytest.fixture
def cloud_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "d" * 40)
    monkeypatch.setenv("SAN_CLOUD_ADMIN_EMAIL", "admin@test.local")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_PASSWORD", "pw-123456")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app, seed_admin_if_configured
    db.init_db()
    seed_admin_if_configured()
    yield create_app()
    db.dispose_engine()
    config.get_cloud_settings.cache_clear()


async def _seed_fleet(client):
    tok = (await client.post("/api/v1/admin/login",
           json={"email": "admin@test.local", "password": "pw-123456"})).json()["access_token"]
    auth = {"Authorization": f"Bearer {tok}"}
    et = (await client.post("/api/v1/admin/enrollment-tokens", json={}, headers=auth)).json()["token"]
    enr = (await client.post("/api/v1/enroll", json={"token": et, "hostname": "host-A"})).json()
    key = {"X-SAN-Endpoint-Key": enr["api_key"]}
    await client.post("/api/v1/ingest", json={
        "events": [
            {"kind": "alert", "severity": "CRITICAL", "decision": "deny",
             "risk_score": 0.98, "reason": "goal hijack", "agent_ref": "payroll-bot",
             "action_name": "transfer_funds", "target_type": "payments"},
            {"kind": "decision", "severity": "INFO", "decision": "allow",
             "risk_score": 0.0, "reason": "ok", "agent_ref": "ci-bot",
             "action_name": "run_tests", "target_type": "shell"},
        ],
        "agents": [{"agent_ref": "payroll-bot", "name": "payroll-bot", "trust_score": 30.0, "status": "active"}],
    }, headers=key)
    return auth, enr["endpoint_id"]


async def test_overview_and_fleet(cloud_app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=cloud_app),
                                 base_url="http://c") as client:
        auth, eid = await _seed_fleet(client)

        ov = (await client.get("/api/v1/admin/overview", headers=auth)).json()
        assert ov["endpoints_total"] == 1
        assert ov["endpoints_online"] == 1
        assert ov["events_24h"] == 2
        assert ov["critical_24h"] == 1

        eps = (await client.get("/api/v1/admin/endpoints", headers=auth)).json()
        assert eps[0]["hostname"] == "host-A"
        assert eps[0]["agent_count"] == 1
        assert eps[0]["status"] == "online"


async def test_endpoint_detail_and_event_search(cloud_app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=cloud_app),
                                 base_url="http://c") as client:
        auth, eid = await _seed_fleet(client)

        detail = (await client.get(f"/api/v1/admin/endpoints/{eid}", headers=auth)).json()
        assert len(detail["events"]) == 2
        assert any(a["agent_ref"] == "payroll-bot" for a in detail["agents"])

        crit = (await client.get("/api/v1/admin/events?severity=CRITICAL", headers=auth)).json()
        assert len(crit) == 1 and crit[0]["agent_ref"] == "payroll-bot"

        found = (await client.get("/api/v1/admin/events?q=hijack", headers=auth)).json()
        assert len(found) == 1

        # Auth is required.
        assert (await client.get("/api/v1/admin/overview")).status_code == 401

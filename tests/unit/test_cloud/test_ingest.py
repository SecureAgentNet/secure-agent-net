"""Phase 3.3 — ingest + heartbeat + the metadata-only privacy guarantee."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "x" * 40)
    monkeypatch.setenv("SAN_CLOUD_ADMIN_EMAIL", "admin@test.local")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_PASSWORD", "pw-123456")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app
    client = TestClient(create_app())
    client.__enter__()
    tok = client.post("/api/v1/admin/login",
                      json={"email": "admin@test.local", "password": "pw-123456"}).json()["access_token"]
    et = client.post("/api/v1/admin/enrollment-tokens", json={},
                     headers={"Authorization": f"Bearer {tok}"}).json()["token"]
    api_key = client.post("/api/v1/enroll", json={"token": et, "hostname": "host-1"}).json()["api_key"]
    yield client, api_key, tok
    client.__exit__(None, None, None)
    db.dispose_engine()
    config.get_cloud_settings.cache_clear()


def test_ingest_requires_endpoint_key(enrolled):
    client, _, _ = enrolled
    r = client.post("/api/v1/ingest", json={"events": []})
    assert r.status_code == 401


def test_ingest_stores_metadata_events(enrolled):
    client, api_key, tok = enrolled
    hdr = {"X-SAN-Endpoint-Key": api_key}
    r = client.post("/api/v1/ingest", json={
        "events": [
            {"kind": "alert", "severity": "CRITICAL", "decision": "deny",
             "risk_score": 0.98, "reason": "goal hijack", "agent_ref": "payroll-bot",
             "action_name": "transfer_funds", "target_type": "payments"},
        ],
        "agents": [{"agent_ref": "payroll-bot", "name": "payroll-bot",
                    "type": "Custom", "trust_score": 40.0, "status": "active"}],
    }, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json() == {"accepted_events": 1, "accepted_agents": 1}

    # It shows up server-side, scoped to the endpoint's tenant.
    from secureagentnet.cloud.db import get_session
    from secureagentnet.cloud import models
    from sqlalchemy import select
    with get_session() as s:
        events = s.execute(select(models.Event)).scalars().all()
        agents = s.execute(select(models.AgentSnapshot)).scalars().all()
    assert len(events) == 1 and events[0].risk_score == 0.98
    assert len(agents) == 1 and agents[0].trust_score == 40.0


def test_payload_or_pii_field_is_REJECTED(enrolled):
    """The core privacy guarantee: an event carrying a non-allowlisted field
    (a raw payload, PII, etc.) is refused with 422 — it can never be stored."""
    client, api_key, _ = enrolled
    hdr = {"X-SAN-Endpoint-Key": api_key}
    for bad in ({"kind": "alert", "payload": {"command": "cat /etc/shadow"}},
                {"kind": "alert", "pii": "alice@example.com"},
                {"kind": "alert", "target_resource": "/root/.ssh/id_rsa"}):
        r = client.post("/api/v1/ingest", json={"events": [bad]}, headers=hdr)
        assert r.status_code == 422, f"expected rejection for {bad}, got {r.status_code}"

    # And nothing leaked into storage.
    from secureagentnet.cloud.db import get_session
    from secureagentnet.cloud import models
    from sqlalchemy import select
    with get_session() as s:
        assert s.execute(select(models.Event)).scalars().all() == []


def test_heartbeat_marks_online_and_returns_command_slot(enrolled):
    client, api_key, _ = enrolled
    r = client.post("/api/v1/heartbeat", json={"agents": [], "threats_blocked": 2},
                    headers={"X-SAN-Endpoint-Key": api_key})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "server_time" in body
    assert body["commands"] == []  # none pending yet (3.5 populates this)

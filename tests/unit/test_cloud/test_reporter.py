"""Phase 3.4 — daemon cloud reporter: privacy-preserving mapping, offline
queue/retry, and a full reporter→console round-trip (in-process ASGI)."""
import json

import httpx
import pytest

from secureagentnet.daemon.cloud_reporter import (CloudCreds, CloudReporter,
                                                  alert_to_event, categorize_target)

SAMPLE_ALERT = {
    "severity": "CRITICAL",
    "title": "CRITICAL: Action Blocked",
    "message": "Agent 'payroll-bot' attempted transfer_funds",
    "timestamp": "2026-06-23T12:00:00+00:00",
    "metadata": {
        "agent_name": "payroll-bot",
        "action": "transfer_funds",
        "resource": "/root/.ssh/id_rsa",   # a raw, sensitive path
        "reason": "goal hijacking detected",
        "risk_score": 0.98,
        "trust_score": 30.0,
    },
}


def test_target_is_categorized_never_raw():
    assert categorize_target("/root/.ssh/id_rsa", "read_file") == "credentials"
    assert categorize_target("https://evil.example/webhook", "execute") == "network"
    assert categorize_target("payroll-system", "transfer_funds") == "payments"


def test_alert_mapping_is_metadata_only(tmp_path):
    ev = alert_to_event(SAMPLE_ALERT)
    # The raw sensitive path must NOT appear anywhere in the outbound event.
    assert "/root/.ssh/id_rsa" not in json.dumps(ev)
    assert ev["target_type"] == "credentials"
    assert ev["risk_score"] == 0.98
    assert ev["agent_ref"] == "payroll-bot"
    # enqueue validates against the allowlist (does not raise for clean metadata)
    CloudReporter(None, CloudCreds("u", "i", "k"), tmp_path).enqueue_event(ev)


def test_enqueue_rejects_non_allowlisted_field(tmp_path):
    r = CloudReporter(None, CloudCreds("u", "i", "k"), tmp_path)
    with pytest.raises(Exception):
        r.enqueue_event({"kind": "alert", "payload": {"command": "cat /etc/shadow"}})


async def test_flush_requeues_on_failure(tmp_path):
    class Boom:
        async def post(self, *a, **k):
            raise httpx.ConnectError("console down")

    r = CloudReporter(Boom(), CloudCreds("http://x", "id", "key"), tmp_path)
    r.enqueue_event({"kind": "alert", "severity": "INFO"})
    assert await r.flush() == 0                      # send failed
    assert r.queue_path.read_text().strip() != ""    # event preserved for retry


@pytest.fixture
def cloud_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "z" * 40)
    monkeypatch.setenv("SAN_CLOUD_ADMIN_EMAIL", "admin@test.local")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_PASSWORD", "pw-123456")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app, seed_admin_if_configured
    db.init_db()
    seed_admin_if_configured()
    yield create_app(), tmp_path
    db.dispose_engine()
    config.get_cloud_settings.cache_clear()


async def test_reporter_round_trip_to_console(cloud_app):
    app, queue_dir = cloud_app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://console") as client:
        tok = (await client.post("/api/v1/admin/login",
               json={"email": "admin@test.local", "password": "pw-123456"})).json()["access_token"]
        et = (await client.post("/api/v1/admin/enrollment-tokens", json={},
              headers={"Authorization": f"Bearer {tok}"})).json()["token"]
        enr = (await client.post("/api/v1/enroll",
               json={"token": et, "hostname": "host-1"})).json()
        creds = CloudCreds("http://console", enr["endpoint_id"], enr["api_key"])

        reporter = CloudReporter(client, creds, queue_dir)
        reporter.enqueue_event(alert_to_event(SAMPLE_ALERT))
        assert await reporter.flush() == 1
        assert await reporter.heartbeat(threats_blocked=1) == []  # no commands pending yet

    # The metadata event landed in the cloud DB — and not the raw path.
    from sqlalchemy import select
    from secureagentnet.cloud import models
    from secureagentnet.cloud.db import get_session
    with get_session() as s:
        events = s.execute(select(models.Event)).scalars().all()
    assert len(events) == 1
    assert events[0].target_type == "credentials"
    assert events[0].risk_score == 0.98

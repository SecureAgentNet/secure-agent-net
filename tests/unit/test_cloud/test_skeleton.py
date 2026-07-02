"""Phase 3.1 — cloud console skeleton: boots, schema, privacy invariant."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app
    with TestClient(create_app()) as c:  # entering the context runs lifespan → init_db
        yield c
    db.dispose_engine()
    config.get_cloud_settings.cache_clear()


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["service"] == "secureagentnet-cloud"


def test_status_reports_empty_fleet(client):
    data = client.get("/api/v1/status").json()
    assert data["status"] == "ok"
    assert data["tenants"] == 0
    assert data["endpoints"] == 0


def test_schema_has_all_core_tables(client):
    from sqlalchemy import inspect
    from secureagentnet.cloud.db import get_engine
    tables = set(inspect(get_engine()).get_table_names())
    assert {
        "tenants", "admin_users", "enrollment_tokens",
        "endpoints", "agent_snapshots", "events", "commands",
    } <= tables


def test_events_table_cannot_store_payloads_or_pii(client):
    # The metadata-only guarantee, asserted structurally: the aggregate store
    # has no column capable of holding a raw payload or PII blob.
    from sqlalchemy import inspect
    from secureagentnet.cloud.db import get_engine
    cols = {c["name"].lower() for c in inspect(get_engine()).get_columns("events")}
    for forbidden in ("payload", "pii", "raw", "content", "body"):
        assert forbidden not in cols

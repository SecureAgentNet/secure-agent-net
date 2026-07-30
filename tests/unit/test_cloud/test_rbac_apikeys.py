"""Pillar D — RBAC, tenant API keys, and usage metering on the Cloud Console."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "test-secret")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_EMAIL", "owner@test.local")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_PASSWORD", "s3cret-pw")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app
    with TestClient(create_app()) as c:
        yield c
    db.dispose_engine()
    config.get_cloud_settings.cache_clear()


def _login(client, email="owner@test.local", pw="s3cret-pw") -> dict:
    r = client.post("/api/v1/admin/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── RBAC ─────────────────────────────────────────────────────────────────────

def test_owner_can_create_users_and_assign_roles(client):
    owner = _login(client)
    r = client.post("/api/v1/admin/users",
                    json={"email": "op@test.local", "password": "pw12345", "role": "operator"},
                    headers=owner)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "operator"


def test_viewer_is_read_only(client):
    owner = _login(client)
    client.post("/api/v1/admin/users",
                json={"email": "viewer@test.local", "password": "pw12345", "role": "viewer"},
                headers=owner)
    viewer = _login(client, "viewer@test.local", "pw12345")

    # Reads allowed.
    assert client.get("/api/v1/admin/overview", headers=viewer).status_code == 200
    # Privileged writes forbidden.
    assert client.post("/api/v1/admin/enrollment-tokens", json={}, headers=viewer).status_code == 403
    assert client.post("/api/v1/admin/users",
                       json={"email": "x@y.z", "password": "pw12345", "role": "viewer"},
                       headers=viewer).status_code == 403


def test_admin_role_can_enroll_but_not_manage_users(client):
    owner = _login(client)
    client.post("/api/v1/admin/users",
                json={"email": "adm@test.local", "password": "pw12345", "role": "admin"},
                headers=owner)
    adm = _login(client, "adm@test.local", "pw12345")

    # 'admin' role may mint enrollment tokens...
    assert client.post("/api/v1/admin/enrollment-tokens", json={}, headers=adm).status_code == 200
    # ...but user management is owner-only.
    assert client.post("/api/v1/admin/users",
                       json={"email": "z@z.z", "password": "pw12345", "role": "viewer"},
                       headers=adm).status_code == 403


# ── API keys + public API ─────────────────────────────────────────────────────

def test_api_key_lifecycle_and_public_api(client):
    owner = _login(client)
    r = client.post("/api/v1/admin/api-keys", json={"name": "ci", "role": "viewer"}, headers=owner)
    assert r.status_code == 201, r.text
    key = r.json()["api_key"]
    assert key.startswith("sank_")

    keyauth = {"Authorization": f"Bearer {key}"}
    assert client.get("/api/v1/public/events", headers=keyauth).status_code == 200
    assert client.get("/api/v1/public/agents", headers=keyauth).status_code == 200

    # Revoke → the same key is now rejected.
    kid = r.json()["id"]
    assert client.post(f"/api/v1/admin/api-keys/{kid}/revoke", headers=owner).status_code == 200
    assert client.get("/api/v1/public/events", headers=keyauth).status_code == 401


def test_creating_api_key_requires_owner(client):
    owner = _login(client)
    client.post("/api/v1/admin/users",
                json={"email": "op2@test.local", "password": "pw12345", "role": "operator"},
                headers=owner)
    op = _login(client, "op2@test.local", "pw12345")
    assert client.post("/api/v1/admin/api-keys", json={"name": "x"}, headers=op).status_code == 403


# ── Usage metering ────────────────────────────────────────────────────────────

def test_ingest_and_api_calls_are_metered(client):
    owner = _login(client)

    # Enrol an endpoint and ingest two events.
    tok = client.post("/api/v1/admin/enrollment-tokens", json={"label": "h1"}, headers=owner).json()["token"]
    enroll = client.post("/api/v1/enroll",
                         json={"token": tok, "hostname": "h1", "platform": "linux"}).json()
    epkey = {"X-SAN-Endpoint-Key": enroll["api_key"]}
    ev = {"kind": "decision", "severity": "INFO", "decision": "allow"}
    r = client.post("/api/v1/ingest", json={"events": [ev, ev], "agents": []}, headers=epkey)
    assert r.status_code == 200, r.text

    # One public-API call (metered).
    key = client.post("/api/v1/admin/api-keys", json={"name": "sdk", "role": "viewer"},
                      headers=owner).json()["api_key"]
    client.get("/api/v1/public/events", headers={"Authorization": f"Bearer {key}"})

    usage = client.get("/api/v1/admin/usage", headers=owner).json()
    assert usage["periods"], "expected a usage counter row"
    current = usage["periods"][0]
    assert current["events_ingested"] == 2
    assert current["api_calls"] >= 1

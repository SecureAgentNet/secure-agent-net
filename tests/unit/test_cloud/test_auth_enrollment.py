"""Phase 3.2 — admin login, enrollment-token issuance, daemon enrollment, key auth."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "test-secret")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_EMAIL", "admin@test.local")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_PASSWORD", "s3cret-pw")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app
    with TestClient(create_app()) as c:
        yield c
    db.dispose_engine()
    config.get_cloud_settings.cache_clear()


def _login(client, pw="s3cret-pw") -> str:
    r = client.post("/api/v1/admin/login", json={"email": "admin@test.local", "password": pw})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_login_succeeds_and_rejects_bad_password(client):
    assert _login(client)
    bad = client.post("/api/v1/admin/login", json={"email": "admin@test.local", "password": "wrong"})
    assert bad.status_code == 401


def test_enrollment_requires_admin_auth(client):
    # No bearer token → rejected.
    assert client.post("/api/v1/admin/enrollment-tokens", json={}).status_code == 401


def test_full_enrollment_flow(client):
    token = _login(client)
    auth = {"Authorization": f"Bearer {token}"}

    # 1. Admin mints an enrollment token.
    r = client.post("/api/v1/admin/enrollment-tokens", json={"label": "laptop-1"}, headers=auth)
    assert r.status_code == 200, r.text
    enroll_token = r.json()["token"]
    assert enroll_token.startswith("san-enroll_")

    # 2. A daemon enrolls with it and receives a per-daemon API key.
    r = client.post("/api/v1/enroll", json={"token": enroll_token, "hostname": "laptop-1", "platform": "linux"})
    assert r.status_code == 200, r.text
    body = r.json()
    api_key = body["api_key"]
    assert api_key.startswith("sane_")
    assert body["endpoint_id"]

    # 3. The endpoint now shows up in the admin's fleet list.
    eps = client.get("/api/v1/admin/endpoints", headers=auth).json()
    assert any(e["hostname"] == "laptop-1" for e in eps)

    # 4. The enrollment token is single-use.
    reuse = client.post("/api/v1/enroll", json={"token": enroll_token, "hostname": "laptop-1"})
    assert reuse.status_code == 401


def test_endpoint_key_auth_dependency(client):
    """require_endpoint accepts a real key and rejects junk (exercised via a tiny probe route)."""
    token = _login(client)
    auth = {"Authorization": f"Bearer {token}"}
    et = client.post("/api/v1/admin/enrollment-tokens", json={}, headers=auth).json()["token"]
    api_key = client.post("/api/v1/enroll", json={"token": et, "hostname": "h"}).json()["api_key"]

    from secureagentnet.cloud.deps import require_endpoint
    from secureagentnet.cloud import models
    # Valid key resolves to an Endpoint.
    ep = require_endpoint(x_san_endpoint_key=api_key)
    assert isinstance(ep, models.Endpoint)
    # Junk key is rejected.
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        require_endpoint(x_san_endpoint_key="sane_not-a-real-key")
    with pytest.raises(HTTPException):
        require_endpoint(x_san_endpoint_key=None)

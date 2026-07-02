"""Phase 3.5 — remote kill-switch: admin issues → daemon pulls → executes → acks."""
import httpx
import pytest

from secureagentnet.daemon.cloud_reporter import CloudCreds, CloudReporter


@pytest.fixture
def cloud_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{tmp_path}/console.db")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "k" * 40)
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


async def _enroll(client):
    tok = (await client.post("/api/v1/admin/login",
           json={"email": "admin@test.local", "password": "pw-123456"})).json()["access_token"]
    auth = {"Authorization": f"Bearer {tok}"}
    et = (await client.post("/api/v1/admin/enrollment-tokens", json={}, headers=auth)).json()["token"]
    enr = (await client.post("/api/v1/enroll", json={"token": et, "hostname": "host-1"})).json()
    return tok, auth, enr


async def test_remote_kill_switch_full_loop(cloud_app):
    app, qdir = cloud_app
    fired = []

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://console") as client:
        tok, auth, enr = await _enroll(client)
        endpoint_id, api_key = enr["endpoint_id"], enr["api_key"]

        # 1. Admin issues a remote kill for this endpoint.
        r = await client.post(f"/api/v1/admin/endpoints/{endpoint_id}/kill",
                              json={"reason": "demo"}, headers=auth)
        assert r.status_code == 200, r.text
        command_id = r.json()["command_id"]

        # 2. Daemon's reporter pulls the command on heartbeat and executes it.
        creds = CloudCreds("http://console", endpoint_id, api_key)
        reporter = CloudReporter(client, creds, qdir,
                                 command_handler=lambda c: fired.append(c["type"]) or "ok")
        commands = await reporter.heartbeat()
        assert [c["type"] for c in commands] == ["kill_switch"]
        for c in commands:
            await reporter.handle_command(c)

    # 3. The handler ran and the command is acked 'done' in the console DB.
    assert fired == ["kill_switch"]
    from sqlalchemy import select
    from secureagentnet.cloud import models
    from secureagentnet.cloud.db import get_session
    with get_session() as s:
        cmd = s.execute(select(models.Command).where(models.Command.id == command_id)).scalar_one()
    assert cmd.status == "done"
    assert cmd.acked_at is not None


async def test_kill_unknown_endpoint_404(cloud_app):
    app, _ = cloud_app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://console") as client:
        _, auth, _ = await _enroll(client)
        import uuid
        r = await client.post(f"/api/v1/admin/endpoints/{uuid.uuid4()}/kill",
                              json={}, headers=auth)
        assert r.status_code == 404


async def test_handler_failure_is_acked_failed(cloud_app):
    app, qdir = cloud_app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://console") as client:
        _, auth, enr = await _enroll(client)
        cmd_id = (await client.post(f"/api/v1/admin/endpoints/{enr['endpoint_id']}/kill",
                  json={}, headers=auth)).json()["command_id"]

        def boom(_c):
            raise RuntimeError("kill switch jammed")

        reporter = CloudReporter(client, CloudCreds("http://console", enr["endpoint_id"], enr["api_key"]),
                                 qdir, command_handler=boom)
        for c in await reporter.heartbeat():
            await reporter.handle_command(c)

    from sqlalchemy import select
    from secureagentnet.cloud import models
    from secureagentnet.cloud.db import get_session
    with get_session() as s:
        cmd = s.execute(select(models.Command).where(models.Command.id == cmd_id)).scalar_one()
    assert cmd.status == "failed"
    assert "jammed" in (cmd.result or "")

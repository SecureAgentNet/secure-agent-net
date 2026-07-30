"""Cloud Console schema migrations (Alembic).

These lock in the guarantee that closing the Pillar-D gap does not depend on
``create_all``: an already-deployed console DB (created before RBAC/API
keys/metering existed) must gain the ``role`` column and the new tables on
upgrade, **without** losing its existing rows.
"""
import sqlite3

from sqlalchemy import create_engine, inspect, text


def _clean_settings(monkeypatch, db_url):
    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", db_url)
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    return config, db


def _columns(db_url, table):
    engine = create_engine(db_url)
    try:
        return {c["name"] for c in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


def _tables(db_url):
    engine = create_engine(db_url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_fresh_db_migrates_to_full_schema(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/fresh.db"
    config, db = _clean_settings(monkeypatch, db_url)
    try:
        db.run_migrations()

        tables = _tables(db_url)
        assert {"tenants", "admin_users", "endpoints", "events", "commands",
                "enrollment_tokens", "agent_snapshots",
                "api_keys", "usage_counters"} <= tables
        # Alembic recorded the version → the DB is now under migration control.
        assert "alembic_version" in tables
        assert "role" in _columns(db_url, "admin_users")
    finally:
        db.dispose_engine()
        config.get_cloud_settings.cache_clear()


def test_legacy_db_gains_pillar_d_without_data_loss(tmp_path, monkeypatch):
    """Simulate a console DB created by an OLD create_all (pre-Pillar-D): baseline
    tables only, an admin row, and no ``role``/``api_keys``/``usage_counters``."""
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(db_path)
    raw.executescript(
        """
        CREATE TABLE tenants (id CHAR(32) PRIMARY KEY, name VARCHAR(200) NOT NULL,
            created_at DATETIME);
        CREATE TABLE admin_users (id CHAR(32) PRIMARY KEY, tenant_id CHAR(32) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME);
        INSERT INTO tenants (id, name) VALUES ('t1', 'acme');
        INSERT INTO admin_users (id, tenant_id, email, password_hash)
            VALUES ('u1', 't1', 'root@acme', 'bcrypt-hash');
        """
    )
    raw.commit()
    raw.close()

    db_url = f"sqlite:///{db_path}"
    assert "role" not in _columns(db_url, "admin_users")  # precondition

    config, db = _clean_settings(monkeypatch, db_url)
    try:
        db.run_migrations()

        # New schema present…
        assert "role" in _columns(db_url, "admin_users")
        assert {"api_keys", "usage_counters"} <= _tables(db_url)

        # …and the pre-existing admin survived, back-filled to tenant owner.
        engine = create_engine(db_url)
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT email, role FROM admin_users WHERE id = 'u1'")
            ).fetchone()
        engine.dispose()
        assert row == ("root@acme", "owner")
    finally:
        db.dispose_engine()
        config.get_cloud_settings.cache_clear()


def test_migrations_are_idempotent(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/idem.db"
    config, db = _clean_settings(monkeypatch, db_url)
    try:
        db.run_migrations()
        # Running again must be a clean no-op (already at head).
        db.run_migrations()
        assert "role" in _columns(db_url, "admin_users")
    finally:
        db.dispose_engine()
        config.get_cloud_settings.cache_clear()


def test_app_boots_on_a_legacy_db(tmp_path, monkeypatch):
    """End-to-end: the console lifespan (init_db) upgrades a legacy DB so the
    RBAC-dependent login/query paths work against a real admin row afterwards."""
    from fastapi.testclient import TestClient

    db_path = tmp_path / "boot.db"
    raw = sqlite3.connect(db_path)
    raw.executescript(
        """
        CREATE TABLE tenants (id CHAR(32) PRIMARY KEY, name VARCHAR(200) NOT NULL,
            created_at DATETIME);
        CREATE TABLE admin_users (id CHAR(32) PRIMARY KEY, tenant_id CHAR(32) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME);
        INSERT INTO tenants (id, name) VALUES ('t1', 'acme');
        """
    )
    raw.commit()
    raw.close()

    monkeypatch.setenv("SAN_CLOUD_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SAN_CLOUD_SECRET_KEY", "test-secret")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_EMAIL", "seed@acme")
    monkeypatch.setenv("SAN_CLOUD_ADMIN_PASSWORD", "seed-pw-123")
    from secureagentnet.cloud import config, db
    config.get_cloud_settings.cache_clear()
    db.dispose_engine()
    from secureagentnet.cloud.app import create_app

    try:
        with TestClient(create_app()) as c:  # lifespan runs init_db → migrations
            # The seed admin (created after migration) can log in and gets a role.
            r = c.post("/api/v1/admin/login",
                       json={"email": "seed@acme", "password": "seed-pw-123"})
            assert r.status_code == 200, r.text
    finally:
        db.dispose_engine()
        config.get_cloud_settings.cache_clear()

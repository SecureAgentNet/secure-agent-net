"""Cloud Console FastAPI application factory.

Phase 3.1 establishes the skeleton: app, DB schema on startup, health/version.
Enrollment, ingest, commands and the dashboard are layered on in 3.2–3.6.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from secureagentnet.cloud import __version__
from secureagentnet.cloud.config import get_cloud_settings
from secureagentnet.cloud.db import get_session, init_db

logger = logging.getLogger("SecureAgentNet.Cloud.API")


def ensure_default_tenant(session, name: str = "default"):
    """Get-or-create the default tenant (single-org for now, schema ready for more)."""
    from sqlalchemy import select
    from secureagentnet.cloud import models
    tenant = session.execute(
        select(models.Tenant).where(models.Tenant.name == name)
    ).scalar_one_or_none()
    if tenant is None:
        tenant = models.Tenant(name=name)
        session.add(tenant)
        session.flush()
    return tenant


def seed_admin_if_configured() -> None:
    """Create the seed admin (and default tenant) if SAN_CLOUD_ADMIN_* are set
    and no admin with that email exists yet."""
    from sqlalchemy import select
    from secureagentnet.cloud import models
    from secureagentnet.cloud.security import hash_password

    settings = get_cloud_settings()
    if not (settings.admin_email and settings.admin_password):
        return
    with get_session() as s:
        exists = s.execute(
            select(models.AdminUser).where(models.AdminUser.email == settings.admin_email)
        ).scalar_one_or_none()
        if exists:
            return
        tenant = ensure_default_tenant(s)
        s.add(models.AdminUser(
            tenant_id=tenant.id,
            email=settings.admin_email,
            password_hash=hash_password(settings.admin_password),
        ))
        logger.info("Seeded admin user %s", settings.admin_email)


def create_app() -> FastAPI:
    settings = get_cloud_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db()
        seed_admin_if_configured()
        logger.info("Cloud Console starting on %s:%s", settings.host, settings.port)
        yield
        logger.info("Cloud Console shutting down")

    app = FastAPI(
        title="SecureAgentNet Cloud Console",
        version=__version__,
        summary="Central console aggregating many SecureAgentNet endpoints.",
        lifespan=lifespan,
    )

    # The dashboard is served same-origin in production; CORS stays permissive
    # for local dev where the Astro dev server runs on a different port.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from secureagentnet.cloud import (routes_admin, routes_enroll, routes_ingest,
                                       routes_public)
    app.include_router(routes_admin.router)
    app.include_router(routes_enroll.router)
    app.include_router(routes_ingest.router)
    app.include_router(routes_public.router)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "secureagentnet-cloud", "version": __version__}

    @app.get("/api/v1/status")
    async def status() -> dict:
        # Lightweight readiness probe that also confirms DB connectivity.
        from sqlalchemy import select
        from secureagentnet.cloud import models
        with get_session() as s:
            tenants = len(s.execute(select(models.Tenant.id)).all())
            endpoints = len(s.execute(select(models.Endpoint.id)).all())
        return {
            "status": "ok",
            "version": __version__,
            "tenants": tenants,
            "endpoints": endpoints,
            "time": datetime.now(timezone.utc).isoformat(),
        }

    # Serve the built Astro dashboard same-origin (mounted last so it never
    # shadows the API routes above). Present only after `npm run build`.
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles
    dashboard_dir = Path(__file__).parent / "dashboard"
    if dashboard_dir.exists():
        app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")
        logger.info("Mounted console dashboard from %s", dashboard_dir)

    return app


app = create_app()

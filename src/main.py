import logging
import sys
import os
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from src.identify.mcp_gateway import router as auth_router, mcp_router
# Flask dashboard disabled (requires Docker/Redis) — use FastAPI + static site instead
# from src.interfaces.web_dashboard.app import app as dashboard_app
from src.interfaces.api import hitl_router, behavior_router, team_router, key_router, config_router, report_router, blog_router, dashboard_router
from src.interfaces.api.metrics import refresh_metrics, generate_latest, init_metrics
from prometheus_client import REGISTRY
from src.identify.identity_registry import IdentityRegistry
from src.track.log_indexer import LogIndexer
from src.core.config import get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("SecureAgentNet")

CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:5000,http://127.0.0.1:5000"
).split(",")


def initialize_system():
    from src.database.connection import init_database
    init_database()
    
    IdentityRegistry.initialize()
    LogIndexer.initialize()
    init_metrics()
    logger.info("SecureAgentNet system initialized.")

    if get_settings().environment == "development":
        from src.database.connection import get_db_session
        from src.database.models import User
        import hashlib
        from uuid import uuid4

        with get_db_session() as session:
            admin_user = session.query(User).filter(User.username == "admin").first()
            if not admin_user:
                admin_user = User(
                    user_id=uuid4(),
                    username="admin",
                    email="admin@secureagentnet.dev",
                    password_hash=hashlib.sha256("admin123".encode()).hexdigest(),
                    role="admin",
                    active=True
                )
                session.add(admin_user)
                session.commit()
                logger.info("Seeded default admin operator (username: admin, password: admin123).")

        if not IdentityRegistry.get_agent_by_name("admin-agent"):
            admin_key = secrets.token_hex(16)
            IdentityRegistry.register_agent({
                "name": "admin-agent",
                "type": "Custom",
                "description": "Built-in admin agent for system management",
                "public_key": admin_key,
                "capabilities": {"level": "admin", "actions": ["*"]},
                "metadata": {"system": True},
                "created_by": "system",
            })
            logger.info("Seeded default admin agent (dev mode only).")


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_system()
    yield


app = FastAPI(
    title="SecureAgentNet API",
    description="Zero-Trust Security Gateway for Autonomous AI Agents (ITCD Pipeline)",
    version="2.0.0",
    lifespan=lifespan,
)

if get_settings().environment == "development":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

app.include_router(auth_router)
app.include_router(mcp_router)
app.include_router(hitl_router)
app.include_router(behavior_router)
app.include_router(team_router)
app.include_router(key_router)
app.include_router(config_router)
app.include_router(report_router)
app.include_router(blog_router)
app.include_router(dashboard_router)

# Flask dashboard disabled — requires Docker/Redis on host
# app.mount("/dashboard", WSGIMiddleware(dashboard_app))


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "SecureAgentNet Gateway",
        "version": "2.0.0",
        "agents_registered": IdentityRegistry.get_total_count(),
        "agents_active": IdentityRegistry.get_active_count(),
    }


@app.get("/api/version")
async def version():
    return {
        "version": "2.0.0",
        "name": "SecureAgentNet",
        "phases": ["IDENTIFY", "TRACK", "CONTAIN", "DECIDE"],
    }


@app.get("/api/diagnostics")
async def diagnostics():
    if get_settings().environment != "development":
        return {"detail": "Not available in production"}
    return {
        "service": "SecureAgentNet Gateway",
        "version": "2.0.0",
        "agents_registered": IdentityRegistry.get_total_count(),
        "agents_active": IdentityRegistry.get_active_count(),
        "events_indexed": len(LogIndexer._events),
    }


@app.get("/metrics")
async def prometheus_metrics():
    refresh_metrics()
    return Response(
        content=generate_latest(REGISTRY),
        media_type="text/plain; charset=utf-8",
    )


@app.post("/api/v1/auth/operator-login")
async def operator_login(username: str, password: str):
    from src.database.connection import get_db_session
    from src.database.models import User
    from src.utils.crypto import create_access_token
    import hashlib
    from datetime import datetime, timezone, timedelta
    from fastapi import HTTPException

    settings = get_settings()
    with get_db_session() as session:
        user = session.query(User).filter(User.username == username, User.active == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if pw_hash != user.password_hash:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user.last_login = datetime.now(timezone.utc)
        session.commit()

        token = create_access_token(
            {
                "sub": str(user.user_id),
                "username": user.username,
                "role": user.role,
            },
            settings.resolve_secret_key(),
            settings.agent_jwt_algorithm,
            expires_delta=timedelta(minutes=480),
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "user_id": str(user.user_id),
                "username": user.username,
                "role": user.role,
            },
        }


@app.get("/api/metrics/summary")
async def metrics_summary():
    return {
        "agents_registered": IdentityRegistry.get_total_count(),
        "agents_active": IdentityRegistry.get_active_count(),
        "events_indexed": len(LogIndexer._events),
        "containers_active": 0,
        "alerts_critical": sum(1 for e in LogIndexer._events if e.get("severity") == "CRITICAL"),
        "uptime_seconds": 0,
    }


@app.get("/api/forensics/search")
async def forensics_search(q: str = "", limit: int = 50):
    events = LogIndexer._events
    if q:
        events = [e for e in events if q.lower() in str(e).lower()]
    return events[-limit:]


uploads_path = Path(__file__).parent.parent / "uploads"
uploads_path.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(uploads_path)), name="uploads")
logger.info("Mounted uploads directory from %s", uploads_path)

# Operator console (must be mounted before the catch-all "/" website mount).
console_path = Path(__file__).parent / "interfaces" / "console"
if console_path.exists():
    app.mount("/console", StaticFiles(directory=str(console_path), html=True), name="console")
    logger.info("Mounted operator console from %s", console_path)

website_path = Path(__file__).parent.parent / "website"
if website_path.exists():
    app.mount("/", StaticFiles(directory=str(website_path), html=True), name="website")
    logger.info("Mounted static website from %s", website_path)
else:
    logger.warning("Website directory not found at %s — static UI unavailable", website_path)


if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
        log_level="info",
    )

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
from starlette.middleware.wsgi import WSGIMiddleware
from contextlib import asynccontextmanager

from src.identify.mcp_gateway import router as auth_router, mcp_router
from src.interfaces.web_dashboard.app import app as dashboard_app
from src.interfaces.api import hitl_router, behavior_router
from src.interfaces.api.metrics import refresh_metrics, generate_latest, init_metrics
from prometheus_client import REGISTRY
from src.identify.identity_registry import IdentityRegistry
from src.track.log_indexer import LogIndexer

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
    IdentityRegistry.initialize()
    LogIndexer.initialize()
    init_metrics()
    logger.info("SecureAgentNet system initialized.")

    if os.environ.get("ENVIRONMENT") == "development" and not IdentityRegistry.get_agent_by_name("admin-agent"):
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

if os.environ.get("ENVIRONMENT") == "development":
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

app.mount("/dashboard", WSGIMiddleware(dashboard_app))


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
    if os.environ.get("ENVIRONMENT") != "development":
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


if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
        log_level="info",
    )

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.wsgi import WSGIMiddleware
from contextlib import asynccontextmanager

from src.identify.mcp_gateway import router as auth_router, mcp_router
from src.interfaces.web_dashboard.app import app as dashboard_app
from src.identify.identity_registry import IdentityRegistry
from src.track.log_indexer import LogIndexer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("SecureAgentNet")


def initialize_system():
    IdentityRegistry.initialize()
    LogIndexer.initialize()
    logger.info("SecureAgentNet system initialized.")

    if not IdentityRegistry.get_agent_by_name("admin-agent"):
        IdentityRegistry.register_agent({
            "name": "admin-agent",
            "type": "Custom",
            "description": "Built-in admin agent for system management",
            "public_key": "",
            "capabilities": {"level": "admin", "actions": ["*"]},
            "metadata": {"system": True},
            "created_by": "system",
        })
        logger.info("Seeded default admin agent.")


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(mcp_router)

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


if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
        log_level="info",
    )

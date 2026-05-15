from fastapi import FastAPI
from src.identify.mcp_gateway import router as auth_router

app = FastAPI(
    title="SecureAgentNet API",
    description="Zero-Trust Security Gateway for Autonomous AI Agents.",
    version="1.0.0"
)

# Register routers
app.include_router(auth_router)

@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "SecureAgentNet Gateway"}

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from secureagentnet.identify.models import (
    ChallengeRequest, ChallengeResponse, LoginRequest,
    TokenResponse, ExecuteRequest, VetRequest,
)
from secureagentnet.identify.authentication import AuthenticationService
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.track.models import AgentActionRequest
from secureagentnet.core.config import get_settings
from secureagentnet.utils.crypto import decode_access_token, create_access_token

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
mcp_router = APIRouter(prefix="/api/v1/mcp", tags=["MCP Protocol"])

security = HTTPBearer(auto_error=False)


async def get_current_agent(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )
    settings = get_settings()
    payload = decode_access_token(
        credentials.credentials,
        settings.resolve_secret_key(),
        settings.agent_jwt_algorithm,
    )
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    agent_id = payload.get("sub")
    if not agent_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    agent = IdentityRegistry.get_agent(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    if agent.get("status") != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent is not active",
        )
    return agent


# --- Unauthenticated Auth Endpoints ---

@router.post("/challenge", response_model=ChallengeResponse)
async def request_challenge(request: ChallengeRequest):
    return AuthenticationService.initiate_challenge(request)


@router.post("/login", response_model=TokenResponse)
async def verify_login(request: LoginRequest):
    return AuthenticationService.verify_and_login(request)


# --- Token Refresh ---

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    settings = get_settings()
    payload = decode_access_token(credentials.credentials, settings.resolve_secret_key(), settings.agent_jwt_algorithm)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    agent_id = payload.get("sub")
    if not agent_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    agent = IdentityRegistry.get_agent(agent_id)
    if not agent or agent.get("status") != "active":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent not found or inactive")
    new_token = create_access_token({"sub": agent_id, "type": "agent"}, settings.resolve_secret_key(), settings.agent_jwt_algorithm)
    return TokenResponse(access_token=new_token)


# --- Protected MCP Protocol Endpoints ---

@mcp_router.get("/tools")
async def list_tools(agent: dict = Depends(get_current_agent)):
    agent_caps = agent.get("capabilities", {})
    tools = [
        {"name": "execute", "description": "Execute a shell command in a sandbox", "args": {"command": "string"}},
        {"name": "read_file", "description": "Read a file from the sandbox", "args": {"path": "string"}},
        {"name": "query", "description": "Query forensic event logs", "args": {"query": "string", "limit": "int"}},
    ]
    filtered = [t for t in tools if t["name"] in agent_caps or "*" in agent_caps.get("actions", [])]
    return {
        "agent_id": agent["agent_id"],
        "tools": filtered if filtered else tools,
        "count": len(filtered if filtered else tools),
    }


@mcp_router.post("/vet")
async def vet_server(request: VetRequest, agent: dict = Depends(get_current_agent)):
    """Vet an external MCP server's tool catalog for tool-poisoning before trust.

    Scans every tool description (and schema field descriptions) for injected
    instructions, exfiltration cues, hidden unicode and rug-pulls, pinning a
    content hash per tool.
    """
    from secureagentnet.identify.mcp_vetting import McpServerRegistry
    verdicts = McpServerRegistry.register_and_vet(request.server_id, request.tools)
    return {
        "server_id": request.server_id,
        "vetted": len(verdicts),
        "malicious": sum(1 for v in verdicts if v.is_malicious),
        "tools": [v.to_dict() for v in verdicts],
    }


@mcp_router.get("/servers")
async def list_vetted_servers(agent: dict = Depends(get_current_agent)):
    """List vetted MCP servers, hiding tools flagged malicious from the agent."""
    from secureagentnet.identify.mcp_vetting import McpServerRegistry, MALICIOUS
    servers = McpServerRegistry.all_servers()
    safe_view = {
        sid: [t for t in tools.values() if t.get("verdict") != MALICIOUS]
        for sid, tools in servers.items()
    }
    return {"servers": safe_view, "count": len(safe_view)}


@mcp_router.post("/execute")
async def execute_tool(request: ExecuteRequest, agent: dict = Depends(get_current_agent)):
    # Trust chain: the agent's signed manifest must verify back to the SAN root
    # authority before any action is considered. A missing, tampered, expired or
    # revoked manifest fails closed.
    from secureagentnet.identify.trust_chain import TrustChainService
    trusted, treason = TrustChainService.verify_agent(agent["agent_id"])
    if not trusted:
        return {"status": "blocked", "reason": f"trust chain verification failed: {treason}",
                "evaluated_by": "TrustChainService", "phase": "IDENTIFY"}

    # External MCP tools must clear vetting (no tool poisoning) AND fall within the
    # agent's commissioned mandate before they ever reach the pipeline.
    if request.server_id:
        from secureagentnet.identify.mcp_vetting import McpServerRegistry
        allowed, reason = McpServerRegistry.is_tool_authorized(
            agent, request.server_id, request.action_name
        )
        if not allowed:
            return {"status": "blocked", "reason": reason,
                    "evaluated_by": "McpToolVetter", "phase": "IDENTIFY"}

    from secureagentnet.core.pipeline import ITCDPipeline
    pipeline = ITCDPipeline()
    command_str = request.payload.get("command", "")
    action_req = AgentActionRequest(
        action_name=request.action_name,
        target_resource=request.target_resource,
        intent_summary=request.intent_summary,
        payload=request.payload,
    )
    result = await pipeline.execute_agent_action(agent["agent_id"], action_req, command_str)
    return result


@mcp_router.get("/agent")
async def get_agent_info(agent: dict = Depends(get_current_agent)):
    return {
        "agent_id": agent["agent_id"],
        "name": agent["name"],
        "type": agent["type"],
        "status": agent["status"],
        "trust_score": agent["trust_score"],
        "capabilities": list(agent.get("capabilities", {}).keys()),
        "registered_at": agent["registered_at"],
        "last_seen": agent.get("last_seen"),
    }


@mcp_router.post("/heartbeat")
async def heartbeat(agent: dict = Depends(get_current_agent)):
    """Agent sends a periodic heartbeat to signal it's still alive."""
    IdentityRegistry.update_agent(agent["agent_id"], {
        "last_seen": datetime.now(timezone.utc).isoformat(),
    })
    return {"status": "ok", "agent_id": agent["agent_id"], "timestamp": datetime.now(timezone.utc).isoformat()}


@mcp_router.get("/capabilities")
async def list_capabilities(agent: dict = Depends(get_current_agent)):
    """List this agent's registered capabilities."""
    from secureagentnet.identify.capability_profiler import CapabilityProfiler
    caps = agent.get("capabilities", {})
    return {"agent_id": agent["agent_id"], "capabilities": caps, "count": len(caps)}

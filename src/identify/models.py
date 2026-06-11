from pydantic import BaseModel, Field
from typing import Optional


class ChallengeRequest(BaseModel):
    """Agent requests a login challenge by providing its public key ID."""
    public_key: str = Field(..., description="The public key or unique identifier of the agent.")


class ChallengeResponse(BaseModel):
    """Gateway provides a one-time nonce to be signed."""
    nonce: str = Field(..., description="A securely generated random string.")
    session_id: str = Field(..., description="Temporary session identifier for the challenge.")


class LoginRequest(BaseModel):
    """Agent submits the cryptographically signed nonce."""
    session_id: str = Field(..., description="The session identifier from the challenge.")
    signature: str = Field(..., description="The cryptographic signature of the nonce.")


class TokenResponse(BaseModel):
    """Gateway issues a short-lived JWT upon successful verification."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(3600, description="Token expiration in seconds.")


class ExecuteRequest(BaseModel):
    """Request to execute a tool through the ITCD pipeline."""
    action_name: str = Field(..., description="Action type (e.g., execute, read_file)")
    target_resource: str = Field("shell", description="Target resource identifier")
    intent_summary: str = Field("", description="Agent's stated intent")
    payload: dict = Field(default_factory=dict, description="Action parameters")
    server_id: Optional[str] = Field(
        None,
        description="If the tool comes from an external MCP server, its id. Triggers "
                    "tool-poisoning vetting + per-tool mandate scoping before execution.",
    )


class VetRequest(BaseModel):
    """Submit an external MCP server's tool catalog for vetting."""
    server_id: str = Field(..., description="Identifier of the MCP server being vetted")
    tools: list = Field(..., description="List of {name, description, input_schema} tool definitions")

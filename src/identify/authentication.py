from typing import Dict, Optional
import uuid

from fastapi import HTTPException, status
from pydantic import BaseModel

from src.core.config import get_settings
from src.identify.models import ChallengeRequest, ChallengeResponse, LoginRequest, TokenResponse
from src.utils.crypto import generate_nonce, generate_session_id, verify_signature, create_access_token

# In-memory store for active challenges (In a real app, this goes to Redis with an expiration TTL)
# Format: {session_id: {"nonce": "...", "public_key": "...", "agent_id": "..."}}
_active_challenges: Dict[str, dict] = {}


# --- Mock Database Interaction ---
# For now, we mock looking up an agent by their public key.
# Later, this will use SQLAlchemy to query the `agents` table.
def get_agent_by_public_key(public_key: str) -> Optional[dict]:
    """Mocks database lookup for an agent using their public key."""
    # Assuming this public key exists in our DB for demonstration
    if "BEGIN PUBLIC KEY" in public_key:
        return {
            "id": str(uuid.uuid4()),
            "name": "Test-Agent-Alpha",
            "public_key": public_key,
            "status": "active"
        }
    return None


class AuthenticationService:
    """Handles the Zero-Trust Challenge-Response logic."""

    @staticmethod
    def initiate_challenge(request: ChallengeRequest) -> ChallengeResponse:
        agent = get_agent_by_public_key(request.public_key)
        
        if not agent:
            # Prevent user enumeration by throwing a generic error, 
            # though in some M2M architectures, a specific 404 is fine.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent identity not found or suspended."
            )

        if agent["status"] != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Agent is not active."
            )

        nonce = generate_nonce()
        session_id = generate_session_id()

        # Store the challenge
        _active_challenges[session_id] = {
            "nonce": nonce,
            "public_key": agent["public_key"],
            "agent_id": agent["id"]
        }

        return ChallengeResponse(nonce=nonce, session_id=session_id)


    @staticmethod
    def verify_and_login(request: LoginRequest) -> TokenResponse:
        challenge_data = _active_challenges.get(request.session_id)

        if not challenge_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session ID."
            )

        # Retrieve challenge info and immediately remove it (prevents replay attacks)
        nonce = challenge_data["nonce"]
        public_key = challenge_data["public_key"]
        agent_id = challenge_data["agent_id"]
        del _active_challenges[request.session_id]

        # Cryptographic verification
        is_valid = verify_signature(
            public_key_pem=public_key, 
            nonce=nonce, 
            signature_hex=request.signature
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid cryptographic signature."
            )

        # Generate JWT
        settings = get_settings()
        jwt_data = {"sub": agent_id, "type": "agent"}
        token = create_access_token(
            data=jwt_data, 
            secret_key=settings.secret_key, 
            algorithm=settings.agent_jwt_algorithm
        )

        return TokenResponse(access_token=token)

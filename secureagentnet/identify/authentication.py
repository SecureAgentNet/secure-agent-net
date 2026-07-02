from typing import Dict, Optional
import hashlib

from fastapi import HTTPException, status

from secureagentnet.core.config import get_settings
from secureagentnet.identify.models import ChallengeRequest, ChallengeResponse, LoginRequest, TokenResponse
from secureagentnet.utils.crypto import generate_nonce, generate_session_id, verify_signature, create_access_token
from secureagentnet.utils.redis_client import set_value, get_value, delete_key, is_available
from secureagentnet.identify.identity_registry import IdentityRegistry

_in_memory_challenges: Dict[str, dict] = {}
CHALLENGE_TTL = 300


def _store_challenge(session_id: str, data: dict):
    if is_available():
        set_value(f"challenge:{session_id}", data, ttl=CHALLENGE_TTL)
    _in_memory_challenges[session_id] = data


def _get_challenge(session_id: str) -> Optional[dict]:
    data = None
    if is_available():
        data = get_value(f"challenge:{session_id}")
    if data is None:
        data = _in_memory_challenges.get(session_id)
    return data


def _remove_challenge(session_id: str):
    if is_available():
        delete_key(f"challenge:{session_id}")
    _in_memory_challenges.pop(session_id, None)


def public_key_fingerprint(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()[:16]


def get_agent_by_public_key(public_key: str) -> Optional[dict]:
    if not public_key or not public_key.strip():
        return None
    agent = IdentityRegistry.get_agent_by_public_key(public_key)
    if agent and agent["status"] == "active":
        return {
            "id": agent["agent_id"],
            "name": agent["name"],
            "public_key": agent["public_key"],
            "status": agent["status"],
            "capabilities": agent.get("capabilities", {}),
        }
    return None


class AuthenticationService:

    @staticmethod
    def initiate_challenge(request: ChallengeRequest) -> ChallengeResponse:
        if not request.public_key or not request.public_key.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Public key is required."
            )

        agent = get_agent_by_public_key(request.public_key)

        if not agent:
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

        _store_challenge(session_id, {
            "nonce": nonce,
            "public_key": agent["public_key"],
            "agent_id": agent["id"]
        })

        return ChallengeResponse(nonce=nonce, session_id=session_id)

    @staticmethod
    def verify_and_login(request: LoginRequest) -> TokenResponse:
        challenge_data = _get_challenge(request.session_id)

        if not challenge_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session ID."
            )

        nonce = challenge_data["nonce"]
        public_key = challenge_data["public_key"]
        agent_id = challenge_data["agent_id"]
        _remove_challenge(request.session_id)

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

        settings = get_settings()
        jwt_data = {"sub": agent_id, "type": "agent"}
        token = create_access_token(
            data=jwt_data,
            secret_key=settings.resolve_secret_key(),
            algorithm=settings.agent_jwt_algorithm
        )

        return TokenResponse(access_token=token)

from fastapi import APIRouter, Depends
from src.identify.models import ChallengeRequest, ChallengeResponse, LoginRequest, TokenResponse
from src.identify.authentication import AuthenticationService

# The main router for Phase 1: Identify
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/challenge", response_model=ChallengeResponse)
async def request_challenge(request: ChallengeRequest):
    """
    Step 1: Agent requests a login challenge by providing its public key.
    The server responds with a random nonce and a session ID.
    """
    return AuthenticationService.initiate_challenge(request)


@router.post("/login", response_model=TokenResponse)
async def verify_login(request: LoginRequest):
    """
    Step 2: Agent submits the signature of the nonce to prove its identity.
    If valid, the server issues a JWT for subsequent API calls.
    """
    return AuthenticationService.verify_and_login(request)

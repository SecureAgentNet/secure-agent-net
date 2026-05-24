import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from src.identify.models import ChallengeRequest, LoginRequest
# noinspection PyProtectedMember
from src.identify.authentication import AuthenticationService, _active_challenges


@pytest.fixture
def rsa_key_pair():
    """Generates a fresh RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key, public_pem


@pytest.fixture
def mock_agent_db(monkeypatch, rsa_key_pair):
    """Mocks the database lookup to return our test agent with the generated public key."""
    _, public_pem = rsa_key_pair
    
    def mock_get_agent(public_key: str):
        if public_key == public_pem:
            return {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Test-Agent",
                "public_key": public_key,
                "status": "active"
            }
        return None
        
    monkeypatch.setattr("src.identify.authentication.get_agent_by_public_key", mock_get_agent)
    return mock_get_agent


def test_initiate_challenge_success(mock_agent_db, rsa_key_pair):
    _ = mock_agent_db 
    _, public_pem = rsa_key_pair
    request = ChallengeRequest(public_key=public_pem)
    
    response = AuthenticationService.initiate_challenge(request)
    
    assert response.nonce is not None
    assert response.session_id is not None
    assert response.session_id in _active_challenges
    assert _active_challenges[response.session_id]["nonce"] == response.nonce


def test_initiate_challenge_invalid_agent(mock_agent_db):
    _ = mock_agent_db
    request = ChallengeRequest(public_key="invalid_key_data")
    
    with pytest.raises(HTTPException) as exc_info:
        AuthenticationService.initiate_challenge(request)
        
    assert exc_info.value.status_code == 401
    assert "Agent identity not found" in exc_info.value.detail


def test_verify_and_login_success(mock_agent_db, rsa_key_pair, monkeypatch):
    _ = mock_agent_db
    # Mock settings so we have a secret key for JWT generation
    class MockSettings:
        secret_key = "test_super_secret"
        agent_jwt_algorithm = "HS256"
        def resolve_secret_key(self):
            return self.secret_key
        
    monkeypatch.setattr("src.identify.authentication.get_settings", MockSettings)

    private_key, public_pem = rsa_key_pair
    
    # Step 1: Initiate Challenge
    challenge_req = ChallengeRequest(public_key=public_pem)
    challenge_resp = AuthenticationService.initiate_challenge(challenge_req)
    
    # Step 2: Sign the nonce using the agent's private key
    nonce_bytes = challenge_resp.nonce.encode('utf-8')
    signature = private_key.sign(
        nonce_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_hex = signature.hex()
    
    # Step 3: Login
    login_req = LoginRequest(
        session_id=challenge_resp.session_id,
        signature=signature_hex
    )
    
    token_resp = AuthenticationService.verify_and_login(login_req)
    
    assert token_resp.access_token is not None
    assert token_resp.token_type == "bearer"
    # Ensure the challenge was consumed (deleted) to prevent replay attacks
    assert challenge_resp.session_id not in _active_challenges


def test_verify_and_login_invalid_signature(mock_agent_db, rsa_key_pair):
    _ = mock_agent_db
    _, public_pem = rsa_key_pair
    
    challenge_req = ChallengeRequest(public_key=public_pem)
    challenge_resp = AuthenticationService.initiate_challenge(challenge_req)
    
    # Send a completely bogus signature
    login_req = LoginRequest(
        session_id=challenge_resp.session_id,
        signature="deadbeef" * 16  # Random hex
    )
    
    with pytest.raises(HTTPException) as exc_info:
        AuthenticationService.verify_and_login(login_req)
        
    assert exc_info.value.status_code == 401
    assert "Invalid cryptographic signature" in exc_info.value.detail
    # Challenge should still be removed even on failure to prevent brute forcing
    assert challenge_resp.session_id not in _active_challenges


def test_verify_and_login_invalid_session(mock_agent_db):
    _ = mock_agent_db
    login_req = LoginRequest(
        session_id="non-existent-session",
        signature="any-signature"
    )

    with pytest.raises(HTTPException) as exc_info:
        AuthenticationService.verify_and_login(login_req)

    assert exc_info.value.status_code == 401
    assert "Invalid or expired session ID" in exc_info.value.detail

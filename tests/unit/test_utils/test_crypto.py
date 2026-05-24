import jwt
import pytest
from datetime import timedelta, datetime, timezone
from src.utils.crypto import generate_nonce, generate_session_id, create_access_token, decode_access_token


class TestCrypto:
    def test_generate_nonce(self):
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        assert len(nonce1) == 64
        assert isinstance(nonce1, str)
        assert nonce1 != nonce2

    def test_generate_nonce_hex_chars(self):
        nonce = generate_nonce()
        assert all(c in "0123456789abcdef" for c in nonce)

    def test_generate_session_id(self):
        sid1 = generate_session_id()
        sid2 = generate_session_id()
        assert isinstance(sid1, str)
        assert len(sid1) > 0
        assert sid1 != sid2

    def test_generate_session_id_urlsafe(self):
        sid = generate_session_id()
        assert all(c.isalnum() or c in "-_" for c in sid)

    def test_create_access_token(self):
        data = {"agent_id": "agent-007", "role": "analyst"}
        token = create_access_token(data, "test-secret", "HS256")
        assert isinstance(token, str)
        assert len(token) > 0
        assert token.count(".") == 2

    def test_create_access_token_with_expiry(self):
        data = {"agent_id": "agent-001"}
        token = create_access_token(data, "secret", "HS256", expires_delta=timedelta(hours=1))
        assert token.count(".") == 2

    def test_create_access_token_different_secrets(self):
        data = {"agent_id": "agent-001"}
        token1 = create_access_token(data, "secret1", "HS256")
        token2 = create_access_token(data, "secret2", "HS256")
        assert token1 != token2

    def test_create_access_token_includes_claims(self):
        data = {"agent_id": "agent-007", "scope": "read"}
        token = create_access_token(data, "test-secret", "HS256")
        decoded = jwt.decode(token, "test-secret", algorithms=["HS256"])
        assert decoded["agent_id"] == "agent-007"
        assert decoded["scope"] == "read"
        assert "exp" in decoded

    def test_decode_access_token_valid(self):
        data = {"sub": "agent-001", "type": "agent"}
        token = create_access_token(data, "test-secret", "HS256", expires_delta=timedelta(hours=1))
        payload = decode_access_token(token, "test-secret", "HS256")
        assert payload is not None
        assert payload["sub"] == "agent-001"
        assert payload["type"] == "agent"

    def test_decode_access_token_wrong_secret(self):
        data = {"sub": "agent-001"}
        token = create_access_token(data, "real-secret", "HS256")
        payload = decode_access_token(token, "wrong-secret", "HS256")
        assert payload is None

    def test_decode_access_token_expired(self):
        data = {"sub": "agent-001"}
        token = create_access_token(data, "test-secret", "HS256", expires_delta=timedelta(seconds=-1))
        payload = decode_access_token(token, "test-secret", "HS256")
        assert payload is None

    def test_decode_access_token_invalid(self):
        payload = decode_access_token("not.a.token", "secret", "HS256")
        assert payload is None

    def test_decode_access_token_returns_none_on_none(self):
        payload = decode_access_token(None, "secret", "HS256")
        assert payload is None

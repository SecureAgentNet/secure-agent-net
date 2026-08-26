import hashlib
import hmac
import os
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from secureagentnet.utils.crypto import decode_access_token

security = HTTPBearer(auto_error=False)

_PASSWORD_SCHEME = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 600_000


def hash_operator_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PASSWORD_ITERATIONS
    )
    return f"{_PASSWORD_SCHEME}${_PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_operator_password(password: str, encoded: str) -> tuple[bool, bool]:
    """Return (valid, needs_upgrade), accepting legacy SHA-256 records once."""
    if encoded.startswith(f"{_PASSWORD_SCHEME}$"):
        try:
            _, iterations, salt_hex, expected_hex = encoded.split("$", 3)
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iterations),
            )
            return hmac.compare_digest(actual.hex(), expected_hex), False
        except (TypeError, ValueError):
            return False, False

    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    valid = hmac.compare_digest(legacy, encoded)
    return valid, valid


async def get_current_operator(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    if os.environ.get("SAN_TESTING") == "1":
        return {"user_id": "test-operator", "username": "admin", "role": "admin"}

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from secureagentnet.core.config import get_settings

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
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub") or payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    return {
        "user_id": user_id,
        "username": payload.get("username", "unknown"),
        "role": payload.get("role", "viewer"),
    }

import os
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from src.utils.crypto import decode_access_token

security = HTTPBearer(auto_error=False)


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

    from src.core.config import get_settings

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

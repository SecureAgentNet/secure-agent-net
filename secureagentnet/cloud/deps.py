"""FastAPI auth dependencies for the Cloud Console."""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from secureagentnet.cloud import models
from secureagentnet.cloud.config import get_cloud_settings
from secureagentnet.cloud.db import get_session
from secureagentnet.cloud.security import hash_secret, read_admin_jwt, role_rank

_bearer = HTTPBearer(auto_error=False)


def require_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Resolve and validate the admin JWT. Returns {admin_id, tenant_id, email, role}."""
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Admin authentication required")
    payload = read_admin_jwt(creds.credentials, get_cloud_settings().secret_key)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired admin token")
    admin_id = payload.get("sub")
    with get_session() as s:
        admin = s.get(models.AdminUser, admin_id)
        if admin is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Admin no longer exists")
        # Trust the DB role so a role change takes effect without re-issuing a token.
        return {"admin_id": str(admin.id), "tenant_id": str(admin.tenant_id),
                "email": admin.email, "role": admin.role or "owner"}


def require_role(minimum: str):
    """Dependency factory: admit only admins whose role ranks at/above `minimum`.

        Depends(require_role("admin"))   # operator/viewer get 403
    """
    def _dep(admin: dict = Depends(require_admin)) -> dict:
        if role_rank(admin.get("role")) < role_rank(minimum):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires '{minimum}' role or higher (you are '{admin.get('role')}')")
        return admin
    return _dep


def require_api_key(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Authenticate a tenant-scoped programmatic API key (public API / SDK).
    Returns {tenant_id, role, key_id}. Touches last_used_at and meters the call."""
    from datetime import datetime, timezone
    from secureagentnet.cloud.metering import record_usage
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key required")
    key_hash = hash_secret(creds.credentials)
    with get_session() as s:
        key = s.execute(
            select(models.ApiKey).where(models.ApiKey.key_hash == key_hash)
        ).scalar_one_or_none()
        if key is None or key.revoked:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key")
        key.last_used_at = datetime.now(timezone.utc)
        result = {"tenant_id": str(key.tenant_id), "role": key.role, "key_id": str(key.id)}
        try:
            record_usage(s, key.tenant_id, api_calls=1)
        except Exception:  # noqa: BLE001 - metering must not break the request
            pass
    return result


def require_endpoint(
    x_san_endpoint_key: Optional[str] = Header(default=None),
) -> models.Endpoint:
    """Resolve the calling endpoint from its per-daemon API key header."""
    if not x_san_endpoint_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Endpoint API key required")
    key_hash = hash_secret(x_san_endpoint_key)
    with get_session() as s:
        endpoint = s.execute(
            select(models.Endpoint).where(models.Endpoint.api_key_hash == key_hash)
        ).scalar_one_or_none()
        if endpoint is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked endpoint key")
        if endpoint.status == "suspended":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Endpoint is suspended")
        return endpoint

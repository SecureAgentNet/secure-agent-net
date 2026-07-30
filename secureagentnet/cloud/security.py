"""Auth primitives for the Cloud Console.

- Admin passwords: bcrypt (salted, slow) — these are low-entropy human secrets.
- Enrollment tokens & per-daemon API keys: high-entropy random strings, stored
  as SHA-256 hashes (fast lookup, no salt needed since they're not guessable).
- Admin sessions: JWT, reusing the gateway's create/decode helpers.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Optional

import bcrypt

from secureagentnet.utils.crypto import create_access_token, decode_access_token

_ALGO = "HS256"

# RBAC role hierarchy, least→most privileged. A dependency requiring role R
# admits any admin whose role ranks at or above R.
ROLES = ("viewer", "operator", "admin", "owner")


def role_rank(role: Optional[str]) -> int:
    """Numeric rank of a role (-1 if unknown), for `>=` comparisons."""
    try:
        return ROLES.index(role)
    except ValueError:
        return -1


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def generate_secret(prefix: str) -> tuple[str, str]:
    """Return (plaintext, sha256_hash). Show the plaintext to the caller once;
    persist only the hash."""
    plaintext = f"{prefix}_{secrets.token_urlsafe(32)}"
    return plaintext, hash_secret(plaintext)


def hash_secret(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def issue_admin_jwt(admin_id: str, tenant_id: str, secret_key: str,
                    role: str = "owner", ttl_hours: int = 12) -> str:
    return create_access_token(
        {"sub": str(admin_id), "tenant": str(tenant_id),
         "typ": "admin", "role": role},
        secret_key, _ALGO, expires_delta=timedelta(hours=ttl_hours),
    )


def read_admin_jwt(token: str, secret_key: str) -> Optional[dict]:
    payload = decode_access_token(token, secret_key, _ALGO)
    if not payload:
        return None
    # `typ == admin` marks a console session; accept legacy tokens whose only
    # marker was role == "admin" so sessions issued before RBAC still validate.
    if payload.get("typ") == "admin" or payload.get("role") == "admin":
        return payload
    return None

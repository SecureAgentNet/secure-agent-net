"""Daemon enrollment: exchange a one-time enrollment token for a per-daemon API key."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from secureagentnet.cloud import models
from secureagentnet.cloud.db import get_session
from secureagentnet.cloud.security import generate_secret, hash_secret

router = APIRouter(prefix="/api/v1", tags=["enroll"])


class EnrollRequest(BaseModel):
    token: str
    hostname: str
    platform: Optional[str] = None


class EnrollResponse(BaseModel):
    endpoint_id: str
    api_key: str        # shown once; the daemon stores it locally


@router.post("/enroll", response_model=EnrollResponse)
def enroll(req: EnrollRequest):
    token_hash = hash_secret(req.token)
    now = datetime.now(timezone.utc)
    with get_session() as s:
        tok = s.execute(
            select(models.EnrollmentToken).where(models.EnrollmentToken.token_hash == token_hash)
        ).scalar_one_or_none()
        if tok is None or tok.used:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or already-used enrollment token")
        if tok.expires_at is not None and _aware(tok.expires_at) < now:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Enrollment token expired")

        api_key, api_key_hash = generate_secret("sane")
        endpoint = models.Endpoint(
            tenant_id=tok.tenant_id,
            hostname=req.hostname,
            platform=req.platform,
            api_key_hash=api_key_hash,
            status="online",
            last_heartbeat=now,
        )
        s.add(endpoint)
        tok.used = True
        s.flush()  # populate endpoint.id before the session closes
        endpoint_id = str(endpoint.id)

    return EnrollResponse(endpoint_id=endpoint_id, api_key=api_key)


def _aware(dt: datetime) -> datetime:
    # SQLite round-trips naive datetimes; treat them as UTC for comparison.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

"""Admin-facing routes: login, enrollment-token issuance, endpoint listing."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select

from secureagentnet.cloud import models
from secureagentnet.cloud.config import get_cloud_settings
from secureagentnet.cloud.db import get_session
from secureagentnet.cloud.deps import require_admin, require_role
from secureagentnet.cloud.metering import current_period
from secureagentnet.cloud.security import (ROLES, generate_secret, hash_password,
                                           issue_admin_jwt, verify_password)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EnrollTokenRequest(BaseModel):
    label: Optional[str] = None
    ttl_hours: int = 24


class EnrollTokenResponse(BaseModel):
    token: str          # shown once
    label: Optional[str]
    expires_at: Optional[str]


@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    with get_session() as s:
        admin = s.execute(
            select(models.AdminUser).where(models.AdminUser.email == req.email)
        ).scalar_one_or_none()
        if admin is None or not verify_password(req.password, admin.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
        token = issue_admin_jwt(admin.id, admin.tenant_id,
                                get_cloud_settings().secret_key,
                                role=admin.role or "owner")
    return LoginResponse(access_token=token)


@router.post("/enrollment-tokens", response_model=EnrollTokenResponse)
def create_enrollment_token(req: EnrollTokenRequest, admin=Depends(require_role("admin"))):
    plaintext, token_hash = generate_secret("san-enroll")
    expires_at = datetime.now(timezone.utc) + timedelta(hours=req.ttl_hours)
    with get_session() as s:
        s.add(models.EnrollmentToken(
            tenant_id=admin["tenant_id"],
            token_hash=token_hash,
            label=req.label,
            expires_at=expires_at,
        ))
    return EnrollTokenResponse(token=plaintext, label=req.label,
                               expires_at=expires_at.isoformat())


class KillRequest(BaseModel):
    reason: Optional[str] = None


@router.post("/endpoints/{endpoint_id}/kill")
def kill_endpoint(endpoint_id: str, req: KillRequest, admin=Depends(require_role("admin"))):
    """Queue a remote kill-switch command for an endpoint. The target daemon
    pulls and executes it on its next heartbeat."""
    with get_session() as s:
        ep = s.execute(
            select(models.Endpoint).where(
                models.Endpoint.id == endpoint_id,
                models.Endpoint.tenant_id == admin["tenant_id"],
            )
        ).scalar_one_or_none()
        if ep is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint not found")
        cmd = models.Command(
            endpoint_id=ep.id, type="kill_switch", status="pending",
            issued_by=admin["email"], reason=req.reason or "Remote kill from console",
        )
        s.add(cmd)
        s.flush()
        return {"command_id": str(cmd.id), "status": "pending"}


def _aware(dt):
    return dt if (dt is None or dt.tzinfo) else dt.replace(tzinfo=timezone.utc)


def _derive_status(ep, timeout_s: int) -> str:
    """Online iff a heartbeat arrived within the timeout; else offline."""
    if ep.status == "suspended":
        return "suspended"
    if ep.last_heartbeat is None:
        return "offline"
    age = (datetime.now(timezone.utc) - _aware(ep.last_heartbeat)).total_seconds()
    return "online" if age < timeout_s else "offline"


def _event_dict(e) -> dict:
    return {
        "id": str(e.id),
        "endpoint_id": str(e.endpoint_id),
        "kind": e.kind,
        "severity": e.severity,
        "decision": e.decision,
        "risk_score": e.risk_score,
        "reason": e.reason,
        "agent_ref": e.agent_ref,
        "action_name": e.action_name,
        "target_type": e.target_type,
        "occurred_at": _iso(e.occurred_at),
        "received_at": _iso(e.received_at),
    }


def _iso(dt):
    return dt.isoformat() if dt else None


@router.get("/overview")
def overview(admin=Depends(require_admin)):
    tid = admin["tenant_id"]
    timeout = get_cloud_settings().heartbeat_timeout_seconds
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    with get_session() as s:
        eps = s.execute(select(models.Endpoint).where(models.Endpoint.tenant_id == tid)).scalars().all()
        online = sum(1 for e in eps if _derive_status(e, timeout) == "online")
        events_24h = s.execute(
            select(func.count()).select_from(models.Event)
            .where(models.Event.tenant_id == tid, models.Event.received_at >= since)
        ).scalar() or 0
        critical_24h = s.execute(
            select(func.count()).select_from(models.Event)
            .where(models.Event.tenant_id == tid, models.Event.severity == "CRITICAL",
                   models.Event.received_at >= since)
        ).scalar() or 0
    return {
        "endpoints_total": len(eps),
        "endpoints_online": online,
        "events_24h": int(events_24h),
        "critical_24h": int(critical_24h),
    }


@router.get("/endpoints")
def list_endpoints(admin=Depends(require_admin)):
    timeout = get_cloud_settings().heartbeat_timeout_seconds
    with get_session() as s:
        rows = s.execute(
            select(models.Endpoint).where(models.Endpoint.tenant_id == admin["tenant_id"])
            .order_by(models.Endpoint.hostname)
        ).scalars().all()
        out = []
        for e in rows:
            agent_count = s.execute(
                select(func.count()).select_from(models.AgentSnapshot)
                .where(models.AgentSnapshot.endpoint_id == e.id)
            ).scalar() or 0
            out.append({
                "id": str(e.id),
                "hostname": e.hostname,
                "platform": e.platform,
                "status": _derive_status(e, timeout),
                "agent_count": int(agent_count),
                "enrolled_at": _iso(e.enrolled_at),
                "last_heartbeat": _iso(e.last_heartbeat),
            })
        return out


@router.get("/endpoints/{endpoint_id}")
def endpoint_detail(endpoint_id: str, admin=Depends(require_admin)):
    timeout = get_cloud_settings().heartbeat_timeout_seconds
    with get_session() as s:
        e = s.execute(
            select(models.Endpoint).where(
                models.Endpoint.id == endpoint_id,
                models.Endpoint.tenant_id == admin["tenant_id"],
            )
        ).scalar_one_or_none()
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint not found")
        agents = s.execute(
            select(models.AgentSnapshot).where(models.AgentSnapshot.endpoint_id == e.id)
            .order_by(models.AgentSnapshot.trust_score)
        ).scalars().all()
        events = s.execute(
            select(models.Event).where(models.Event.endpoint_id == e.id)
            .order_by(models.Event.received_at.desc()).limit(50)
        ).scalars().all()
        return {
            "id": str(e.id),
            "hostname": e.hostname,
            "platform": e.platform,
            "status": _derive_status(e, timeout),
            "enrolled_at": _iso(e.enrolled_at),
            "last_heartbeat": _iso(e.last_heartbeat),
            "agents": [{
                "agent_ref": a.agent_ref, "name": a.name, "type": a.type,
                "trust_score": a.trust_score, "status": a.status,
                "updated_at": _iso(a.updated_at),
            } for a in agents],
            "events": [_event_dict(ev) for ev in events],
        }


@router.get("/events")
def list_events(admin=Depends(require_admin), severity: Optional[str] = None,
                endpoint_id: Optional[str] = None, q: Optional[str] = None,
                limit: int = 100):
    limit = max(1, min(limit, 500))
    with get_session() as s:
        stmt = select(models.Event).where(models.Event.tenant_id == admin["tenant_id"])
        if severity:
            stmt = stmt.where(models.Event.severity == severity.upper())
        if endpoint_id:
            stmt = stmt.where(models.Event.endpoint_id == endpoint_id)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(
                models.Event.reason.ilike(like),
                models.Event.action_name.ilike(like),
                models.Event.agent_ref.ilike(like),
            ))
        stmt = stmt.order_by(models.Event.received_at.desc()).limit(limit)
        rows = s.execute(stmt).scalars().all()
        return [_event_dict(e) for e in rows]


# ── Team management (RBAC) ───────────────────────────────────────────────────
class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str = "operator"


class SetRoleRequest(BaseModel):
    role: str


@router.get("/users")
def list_users(admin=Depends(require_role("admin"))):
    with get_session() as s:
        rows = s.execute(
            select(models.AdminUser).where(models.AdminUser.tenant_id == admin["tenant_id"])
        ).scalars().all()
        return [{"id": str(u.id), "email": u.email, "role": u.role} for u in rows]


@router.post("/users", status_code=201)
def create_user(req: CreateUserRequest, admin=Depends(require_role("owner"))):
    """Invite a teammate to this tenant with a role. Owner-only."""
    if req.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"role must be one of {ROLES}")
    with get_session() as s:
        exists = s.execute(
            select(models.AdminUser).where(models.AdminUser.email == req.email)
        ).scalar_one_or_none()
        if exists is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
        user = models.AdminUser(
            tenant_id=admin["tenant_id"], email=req.email,
            password_hash=hash_password(req.password), role=req.role)
        s.add(user)
        s.flush()
        return {"id": str(user.id), "email": user.email, "role": user.role}


@router.patch("/users/{user_id}")
def set_user_role(user_id: str, req: SetRoleRequest, admin=Depends(require_role("owner"))):
    if req.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"role must be one of {ROLES}")
    with get_session() as s:
        user = s.execute(
            select(models.AdminUser).where(
                models.AdminUser.id == user_id,
                models.AdminUser.tenant_id == admin["tenant_id"],
            )
        ).scalar_one_or_none()
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        user.role = req.role
        return {"id": str(user.id), "email": user.email, "role": user.role}


# ── Programmatic API keys (public API / SDK) ─────────────────────────────────
class CreateApiKeyRequest(BaseModel):
    name: str
    role: str = "viewer"


@router.get("/api-keys")
def list_api_keys(admin=Depends(require_role("admin"))):
    with get_session() as s:
        rows = s.execute(
            select(models.ApiKey).where(models.ApiKey.tenant_id == admin["tenant_id"])
        ).scalars().all()
        return [{
            "id": str(k.id), "name": k.name, "prefix": k.key_prefix, "role": k.role,
            "revoked": bool(k.revoked),
            "last_used_at": _iso(k.last_used_at), "created_at": _iso(k.created_at),
        } for k in rows]


@router.post("/api-keys", status_code=201)
def create_api_key(req: CreateApiKeyRequest, admin=Depends(require_role("owner"))):
    """Mint a tenant API key for the public API/SDK. The plaintext is shown once."""
    if req.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"role must be one of {ROLES}")
    plaintext, key_hash = generate_secret("sank")
    prefix = plaintext[:12]
    with get_session() as s:
        key = models.ApiKey(
            tenant_id=admin["tenant_id"], name=req.name, key_prefix=prefix,
            key_hash=key_hash, role=req.role)
        s.add(key)
        s.flush()
        return {"id": str(key.id), "name": key.name, "role": key.role,
                "api_key": plaintext, "prefix": prefix}


@router.post("/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: str, admin=Depends(require_role("owner"))):
    with get_session() as s:
        key = s.execute(
            select(models.ApiKey).where(
                models.ApiKey.id == key_id,
                models.ApiKey.tenant_id == admin["tenant_id"],
            )
        ).scalar_one_or_none()
        if key is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
        key.revoked = True
        return {"id": str(key.id), "revoked": True}


# ── Usage / metering (billing surface) ───────────────────────────────────────
@router.get("/usage")
def usage(admin=Depends(require_role("admin"))):
    """Current-period and recent usage counters for this tenant."""
    with get_session() as s:
        rows = s.execute(
            select(models.UsageCounter)
            .where(models.UsageCounter.tenant_id == admin["tenant_id"])
            .order_by(models.UsageCounter.period.desc())
            .limit(12)
        ).scalars().all()
        periods = [{
            "period": c.period, "events_ingested": c.events_ingested,
            "api_calls": c.api_calls, "updated_at": _iso(c.updated_at),
        } for c in rows]
    return {"current_period": current_period(), "periods": periods}

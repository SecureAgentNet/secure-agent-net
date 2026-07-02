import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from typing import Optional

from secureagentnet.database.connection import get_db_session
from secureagentnet.database.models import User
from secureagentnet.interfaces.api.auth import get_current_operator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/team", tags=["Team"])


class OperatorResponse(BaseModel):
    user_id: str
    username: str
    email: str
    role: str
    active: bool
    created_at: Optional[str] = None
    last_login: Optional[str] = None

    class Config:
        from_attributes = True


class CreateOperatorRequest(BaseModel):
    username: str
    email: str
    role: str = "viewer"
    password: str


class UpdateOperatorRoleRequest(BaseModel):
    role: str


def _serialize_user(user: User) -> dict:
    return {
        "user_id": str(user.user_id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "active": bool(user.active),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


@router.get("", response_model=list[OperatorResponse])
def list_operators(_operator: dict = Depends(get_current_operator)):
    with get_db_session() as session:
        users = session.query(User).all()
        return [_serialize_user(u) for u in users]


@router.post("", response_model=OperatorResponse, status_code=201)
def create_operator(body: CreateOperatorRequest, _operator: dict = Depends(get_current_operator)):
    import hashlib
    import uuid as _uuid
    with get_db_session() as session:
        existing = session.query(User).filter(
            (User.username == body.username) | (User.email == body.email)
        ).first()
        if existing:
            raise HTTPException(status_code=409, detail="Username or email already exists")

        user = User(
            user_id=_uuid.uuid4(),
            username=body.username,
            email=body.email,
            password_hash=hashlib.sha256(body.password.encode()).hexdigest(),
            role=body.role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info("Created operator %s with role %s", body.username, body.role)
        return _serialize_user(user)


@router.put("/{user_id}/role", response_model=OperatorResponse)
def update_operator_role(user_id: str, body: UpdateOperatorRoleRequest, _operator: dict = Depends(get_current_operator)):
    valid_roles = {"admin", "operator", "auditor", "viewer"}
    if body.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")

    with get_db_session() as session:
        user = session.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Operator not found")
        user.role = body.role
        session.commit()
        session.refresh(user)
        logger.info("Updated operator %s role to %s", user.username, body.role)
        return _serialize_user(user)


@router.delete("/{user_id}", status_code=204)
def deactivate_operator(user_id: str, _operator: dict = Depends(get_current_operator)):
    with get_db_session() as session:
        user = session.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Operator not found")
        user.active = False
        session.commit()
        logger.info("Deactivated operator %s", user.username)

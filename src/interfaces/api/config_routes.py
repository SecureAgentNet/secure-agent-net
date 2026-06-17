import logging
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from src.database.connection import get_db_session
from src.database.models import Policy
from src.interfaces.api.auth import get_current_operator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/itcd/config", tags=["ITCD Configuration"])


class ITCDConfigResponse(BaseModel):
    id: str
    name: str
    action_type: str
    conditions: dict
    priority: int
    active: bool

    class Config:
        from_attributes = True


class SandboxLimitsResponse(BaseModel):
    cpu_limit: str = "1.0"
    memory_limit_mb: int = 512
    network_mode: str = "restricted"
    read_only_root: bool = True
    max_execution_time_ms: int = 30000


class PIISettingsResponse(BaseModel):
    enabled: bool = True
    redaction_level: str = "strict"
    custom_patterns: list[str] = []


class GateConfigResponse(BaseModel):
    model_name: str = "llama3.2:7b"
    confidence_threshold: float = 0.7
    max_tokens: int = 256


class FullITCDConfigResponse(BaseModel):
    policies: list[ITCDConfigResponse]
    sandbox: SandboxLimitsResponse
    pii: PIISettingsResponse
    gate: GateConfigResponse


class UpdatePolicyRequest(BaseModel):
    name: str
    action_type: str
    conditions: dict
    priority: int = 0


class UpdateSandboxRequest(BaseModel):
    cpu_limit: Optional[str] = None
    memory_limit_mb: Optional[int] = None
    network_mode: Optional[str] = None
    read_only_root: Optional[bool] = None
    max_execution_time_ms: Optional[int] = None


class UpdatePIIRequest(BaseModel):
    enabled: Optional[bool] = None
    redaction_level: Optional[str] = None
    custom_patterns: Optional[list[str]] = None


# Simple file-backed config store for sandbox/PII/gate settings
import os
import json

_config_dir = os.path.expanduser("~/.secureagentnet/config")
os.makedirs(_config_dir, exist_ok=True)
_config_path = os.path.join(_config_dir, "itcd_config.json")


def _load_config() -> dict:
    if os.path.exists(_config_path):
        with open(_config_path) as f:
            return json.load(f)
    return {}


def _save_config(config: dict):
    with open(_config_path, "w") as f:
        json.dump(config, f, indent=2)


@router.get("", response_model=FullITCDConfigResponse)
def get_itcd_config(_operator: dict = Depends(get_current_operator)):
    with get_db_session() as session:
        policies = session.query(Policy).all()
        policy_list = [
            ITCDConfigResponse(
                id=str(p.id),
                name=p.name,
                action_type=p.action_type,
                conditions=p.conditions or {},
                priority=p.priority or 0,
                active=True,
            )
            for p in policies
        ]

    cfg = _load_config()
    sandbox = SandboxLimitsResponse(
        cpu_limit=cfg.get("sandbox", {}).get("cpu_limit", "1.0"),
        memory_limit_mb=cfg.get("sandbox", {}).get("memory_limit_mb", 512),
        network_mode=cfg.get("sandbox", {}).get("network_mode", "restricted"),
        read_only_root=cfg.get("sandbox", {}).get("read_only_root", True),
        max_execution_time_ms=cfg.get("sandbox", {}).get("max_execution_time_ms", 30000),
    )
    pii = PIISettingsResponse(
        enabled=cfg.get("pii", {}).get("enabled", True),
        redaction_level=cfg.get("pii", {}).get("redaction_level", "strict"),
        custom_patterns=cfg.get("pii", {}).get("custom_patterns", []),
    )
    gate = GateConfigResponse(
        model_name=cfg.get("gate", {}).get("model_name", "llama3.2:7b"),
        confidence_threshold=cfg.get("gate", {}).get("confidence_threshold", 0.7),
        max_tokens=cfg.get("gate", {}).get("max_tokens", 256),
    )

    return FullITCDConfigResponse(policies=policy_list, sandbox=sandbox, pii=pii, gate=gate)


@router.put("/sandbox", response_model=SandboxLimitsResponse)
def update_sandbox(body: UpdateSandboxRequest, _operator: dict = Depends(get_current_operator)):
    cfg = _load_config()
    sandbox = cfg.get("sandbox", {})
    if body.cpu_limit is not None:
        sandbox["cpu_limit"] = body.cpu_limit
    if body.memory_limit_mb is not None:
        sandbox["memory_limit_mb"] = body.memory_limit_mb
    if body.network_mode is not None:
        sandbox["network_mode"] = body.network_mode
    if body.read_only_root is not None:
        sandbox["read_only_root"] = body.read_only_root
    if body.max_execution_time_ms is not None:
        sandbox["max_execution_time_ms"] = body.max_execution_time_ms
    cfg["sandbox"] = sandbox
    _save_config(cfg)
    logger.info("Updated sandbox config: %s", sandbox)
    return SandboxLimitsResponse(**sandbox)


@router.put("/pii", response_model=PIISettingsResponse)
def update_pii(body: UpdatePIIRequest, _operator: dict = Depends(get_current_operator)):
    cfg = _load_config()
    pii_settings = cfg.get("pii", {})
    if body.enabled is not None:
        pii_settings["enabled"] = body.enabled
    if body.redaction_level is not None:
        pii_settings["redaction_level"] = body.redaction_level
    if body.custom_patterns is not None:
        pii_settings["custom_patterns"] = body.custom_patterns
    cfg["pii"] = pii_settings
    _save_config(cfg)
    logger.info("Updated PII settings")
    return PIISettingsResponse(**pii_settings)


@router.put("/policies", status_code=201)
def add_policy(body: UpdatePolicyRequest, _operator: dict = Depends(get_current_operator)):
    with get_db_session() as session:
        policy = Policy(
            id=uuid4(),
            name=body.name,
            action_type=body.action_type,
            conditions=body.conditions,
            priority=body.priority,
        )
        session.add(policy)
        session.commit()
        session.refresh(policy)
        logger.info("Added policy: %s", body.name)
        return ITCDConfigResponse(
            id=str(policy.id),
            name=policy.name,
            action_type=policy.action_type,
            conditions=policy.conditions or {},
            priority=policy.priority or 0,
            active=True,
        )


@router.delete("/policies/{policy_id}", status_code=204)
def remove_policy(policy_id: str, _operator: dict = Depends(get_current_operator)):
    with get_db_session() as session:
        policy = session.query(Policy).filter(Policy.id == policy_id).first()
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        session.delete(policy)
        session.commit()
        logger.info("Removed policy: %s", policy_id)

from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/hitl", tags=["HITL Console"])


@router.get("/pending")
async def list_pending_requests():
    from secureagentnet.decide.hitl import get_hitl_gate

    gate = get_hitl_gate()
    pending = gate.get_all_pending()
    return {
        "total": len(pending),
        "requests": pending,
    }


@router.post("/approve/{request_id}")
async def approve_request(request_id: str):
    from secureagentnet.decide.hitl import get_hitl_gate, HITLDecision

    gate = get_hitl_gate()
    decision = gate.approve(request_id, operator="api")

    if decision == HITLDecision.TIMED_OUT:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Request {request_id} not found or already timed out",
        )

    return {
        "request_id": request_id,
        "decision": decision.value,
        "request": gate.get_pending_request(request_id),
    }


@router.post("/deny/{request_id}")
async def deny_request(request_id: str):
    from secureagentnet.decide.hitl import get_hitl_gate, HITLDecision

    gate = get_hitl_gate()
    decision = gate.deny(request_id, operator="api")

    if decision == HITLDecision.TIMED_OUT:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Request {request_id} not found or already timed out",
        )

    return {
        "request_id": request_id,
        "decision": decision.value,
        "request": gate.get_pending_request(request_id),
    }


@router.get("/summary")
async def hitl_summary():
    from secureagentnet.decide.hitl import get_hitl_gate

    gate = get_hitl_gate()
    return {
        "pending_count": gate.pending_count,
        "timeout_seconds": 60,
    }

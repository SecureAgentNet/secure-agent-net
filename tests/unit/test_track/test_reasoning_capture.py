import pytest
from secureagentnet.track.models import AgentActionRequest
from secureagentnet.track.reasoning_capture import ReasoningCaptureMiddleware
from secureagentnet.core.exceptions import PipelineBlockedError


@pytest.mark.asyncio
async def test_capture_and_evaluate_success(monkeypatch):
    class MockAuditor:
        def capture(self, log_event):
            log_event.vault_receipt_id = "mock-receipt-123"
            return log_event

    monkeypatch.setattr("secureagentnet.track.reasoning_capture.auditor", MockAuditor())

    async def mock_execute():
        return {"file_contents": "secret data"}

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="secrets.txt",
        intent_summary="Reading secrets",
        payload={},
    )

    result = await ReasoningCaptureMiddleware.capture_and_evaluate(
        agent_id="test-agent",
        request=request,
        execute_callback=mock_execute,
    )

    assert result["status"] == "success"
    assert result["vault_receipt"] == "mock-receipt-123"
    assert result["data"]["file_contents"] == "secret data"


@pytest.mark.asyncio
async def test_capture_and_evaluate_failure(monkeypatch):
    class MockAuditor:
        def capture(self, log_event):
            log_event.vault_receipt_id = "mock-receipt-456"
            return log_event

    monkeypatch.setattr("secureagentnet.track.reasoning_capture.auditor", MockAuditor())

    async def mock_execute_fail():
        raise PermissionError("Agent does not have access to this resource.")

    request = AgentActionRequest(
        action_name="delete_database",
        target_resource="prod_db",
        intent_summary="Cleaning up",
        payload={},
    )

    result = await ReasoningCaptureMiddleware.capture_and_evaluate(
        agent_id="rogue-agent",
        request=request,
        execute_callback=mock_execute_fail,
    )

    assert result["status"] == "error"
    assert result["vault_receipt"] == "mock-receipt-456"
    assert "Agent does not have access" in result["error_details"]


@pytest.mark.asyncio
async def test_capture_and_evaluate_blocked(monkeypatch):
    class MockAuditor:
        def capture(self, log_event):
            log_event.vault_receipt_id = "mock-receipt-789"
            return log_event

    monkeypatch.setattr("secureagentnet.track.reasoning_capture.auditor", MockAuditor())

    async def mock_execute_blocked():
        raise PipelineBlockedError(
            reason="High risk command detected",
            evaluated_by="SemanticEvaluator",
            risk_score=0.95,
        )

    request = AgentActionRequest(
        action_name="rm_rf",
        target_resource="/",
        intent_summary="Cleanup",
        payload={},
    )

    result = await ReasoningCaptureMiddleware.capture_and_evaluate(
        agent_id="bad-agent",
        request=request,
        execute_callback=mock_execute_blocked,
    )

    assert result["status"] == "blocked"
    assert result["vault_receipt"] == "mock-receipt-789"
    assert result["reason"] == "High risk command detected"
    assert result["risk_score"] == 0.95

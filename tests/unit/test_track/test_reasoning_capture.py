import pytest
from src.track.models import AgentActionRequest
from src.track.reasoning_capture import ReasoningCaptureMiddleware


@pytest.mark.asyncio
async def test_capture_and_evaluate_success(monkeypatch):
    # Mock the auditor so we don't need Vault
    class MockAuditor:
        def capture(self, log_event):
            log_event.vault_receipt_id = "mock-receipt-123"
            return log_event
            
    monkeypatch.setattr("src.track.reasoning_capture.auditor", MockAuditor())
    
    # Mock execution callback
    async def mock_execute():
        return {"file_contents": "secret data"}
        
    request = AgentActionRequest(
        action_name="read_file",
        target_resource="secrets.txt",
        intent_summary="Reading secrets",
        payload={}
    )
    
    result = await ReasoningCaptureMiddleware.capture_and_evaluate(
        agent_id="test-agent",
        request=request,
        execute_callback=mock_execute
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
            
    monkeypatch.setattr("src.track.reasoning_capture.auditor", MockAuditor())
    
    # Mock execution callback that raises an exception
    async def mock_execute_fail():
        raise PermissionError("Agent does not have access to this resource.")
        
    request = AgentActionRequest(
        action_name="delete_database",
        target_resource="prod_db",
        intent_summary="Cleaning up",
        payload={}
    )
    
    result = await ReasoningCaptureMiddleware.capture_and_evaluate(
        agent_id="rogue-agent",
        request=request,
        execute_callback=mock_execute_fail
    )
    
    assert result["status"] == "error"
    assert result["vault_receipt"] == "mock-receipt-456"
    assert "Agent does not have access" in result["error_details"]

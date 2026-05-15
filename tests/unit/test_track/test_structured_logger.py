import pytest
import json
from unittest.mock import MagicMock
from src.track.models import AgentActionRequest, CapturedLog
from src.track.structured_logger import AgentAuditor
from src.track.vault_client import VaultAuditClient

def test_agent_auditor_capture(monkeypatch):
    # Mock the Vault Client so we don't actually hit a Vault server during unit tests
    mock_vault = MagicMock()
    mock_vault.secure_log.return_value = "vault-audit/agents/123/456-v1"

    # Patch the VaultAuditClient instantiation inside AgentAuditor
    monkeypatch.setattr("src.track.structured_logger.VaultAuditClient", lambda: mock_vault)

    auditor = AgentAuditor()

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="/etc/passwd",
        intent_summary="I need to check system users.",
        payload={"path": "/etc/passwd"}
    )

    log_event = CapturedLog(
        agent_id="agent-007",
        action_request=request
    )

    # Execute the capture
    captured = auditor.capture(log_event)

    # Assertions
    assert captured.vault_receipt_id == "vault-audit/agents/123/456-v1"
    mock_vault.secure_log.assert_called_once()

    # Verify the payload passed to secure_log was a dictionary
    args, _ = mock_vault.secure_log.call_args
    passed_dict = args[0]
    assert passed_dict["agent_id"] == "agent-007"
    assert passed_dict["action_request"]["action_name"] == "read_file"

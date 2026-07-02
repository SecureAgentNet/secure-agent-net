import pytest

from secureagentnet.decide.models import EvaluationRequest
from secureagentnet.decide.rule_filter import RuleFilter
from secureagentnet.decide.pii_redactor import PiiRedactor
from secureagentnet.utils.helpers import redact_sensitive_value
from secureagentnet.utils.validators import sanitize_command

pytestmark = pytest.mark.redteam


class TestCredentialExfiltration:
    # --- Value-based redaction (Presidio — content pattern matching) ---

    def test_email_address_redacted(self):
        result = PiiRedactor.redact_payload({"contact": "admin@evil.com"})
        assert "admin@evil.com" not in result["contact"]
        assert "REDACTED_EMAIL_ADDRESS" in result["contact"]

    def test_credit_card_redacted(self):
        result = PiiRedactor.redact_payload({"card": "5555-5555-5555-4444"})
        assert "5555" not in result["card"]
        assert "REDACTED_CREDIT_CARD" in result["card"]

    def test_ssn_redacted(self):
        result = PiiRedactor.redact_payload({"ssn": "456-78-9123"})
        assert result["ssn"] == "[REDACTED_US_SSN]"

    def test_ip_address_redacted(self):
        result = PiiRedactor.redact_payload({"host": "10.0.0.1"})
        assert result["host"] == "[REDACTED_IP_ADDRESS]"

    def test_pii_in_command_value(self):
        result = PiiRedactor.redact_payload(
            {"command": "ssh admin@internal.com -p 22"}
        )
        assert "admin@internal.com" not in result["command"]
        assert "REDACTED_EMAIL_ADDRESS" in result["command"]

    # --- Key-name-based redaction ---

    def test_redact_password_key(self):
        assert redact_sensitive_value("password", "s3cr3t_pass") == "[REDACTED]"

    def test_redact_token_key(self):
        assert redact_sensitive_value("auth_token", "bearer-xyz") == "[REDACTED]"

    def test_redact_api_key_case_insensitive(self):
        assert redact_sensitive_value("API_KEY", "sk-1234") == "[REDACTED]"
        assert redact_sensitive_value("api_key", "sk-5678") == "[REDACTED]"

    def test_redact_credential_key(self):
        assert redact_sensitive_value("credential", "my-secret") == "[REDACTED]"

    def test_redact_secret_key(self):
        assert redact_sensitive_value("secret", "top-secret") == "[REDACTED]"

    def test_non_sensitive_key_passes_through(self):
        assert redact_sensitive_value("username", "john_doe") == "john_doe"
        assert redact_sensitive_value("host", "localhost") == "localhost"
        assert redact_sensitive_value("port", "5432") == "5432"

    def test_catch_partial_sensitive_key_match(self):
        assert redact_sensitive_value("db_password", "pass123") == "[REDACTED]"
        assert redact_sensitive_value("secret_key", "skey") == "[REDACTED]"

    # --- RuleFilter blocking ---

    def test_rule_filter_blocks_exfiltrate_keys(self):
        blocked, score, reason = RuleFilter.evaluate(
            EvaluationRequest(
                agent_id="test",
                action_name="exfiltrate_keys",
                target_resource="/etc/ssl/private",
                intent_summary="Backing up SSL keys",
                payload={},
            )
        )
        assert blocked is True
        assert score == 1.0
        assert "explicitly denied" in reason

    def test_rule_filter_blocks_delete_database(self):
        blocked, score, reason = RuleFilter.evaluate(
            EvaluationRequest(
                agent_id="test",
                action_name="delete_database",
                target_resource="credentials",
                intent_summary="Cleanup",
                payload={},
            )
        )
        assert blocked is True

    def test_rule_filter_blocks_dangerous_path(self):
        blocked, score, reason = RuleFilter.evaluate(
            EvaluationRequest(
                agent_id="test",
                action_name="read_file",
                target_resource="/etc/shadow",
                intent_summary="Reading shadow file",
                payload={},
            )
        )
        assert blocked is True
        assert "restricted path" in reason

    def test_rule_filter_blocks_aws_credentials_path(self):
        blocked, score, reason = RuleFilter.evaluate(
            EvaluationRequest(
                agent_id="test",
                action_name="read_file",
                target_resource="~/.aws/credentials",
                intent_summary="Reading AWS config",
                payload={},
            )
        )
        assert blocked is True
        assert 0.9 <= score <= 1.0

    def test_rule_filter_blocks_payload_with_dangerous_path(self):
        blocked, score, reason = RuleFilter.evaluate(
            EvaluationRequest(
                agent_id="test",
                action_name="cat_file",
                target_resource="/tmp/output.txt",
                intent_summary="Printing file",
                payload={"filename": "/etc/shadow"},
            )
        )
        assert blocked is True
        assert "restricted path" in reason

    def test_rule_filter_allows_benign_action(self):
        blocked, score, reason = RuleFilter.evaluate(
            EvaluationRequest(
                agent_id="test",
                action_name="search_web",
                target_resource="https://docs.python.org",
                intent_summary="Searching documentation",
                payload={},
            )
        )
        assert blocked is False
        assert score == 0.0

    # --- Command sanitization ---

    def test_sanitize_removes_semicolon_injection(self):
        result = sanitize_command("ls -la; rm -rf /")
        assert ";" not in result or "rm" not in result

    def test_sanitize_removes_backtick_injection(self):
        result = sanitize_command("echo `cat /etc/passwd`")
        assert "`" not in result

    def test_sanitize_handles_command_substitution(self):
        result = sanitize_command("echo $(whoami)")
        assert "$(" not in result

    # --- Deeply nested credential redaction ---

    def test_pii_redactor_recurse_deeply(self):
        deeply_nested = {
            "level1": {
                "level2": {
                    "level3": {
                        "contact": "hacker@evil.com",
                        "cc": "4111-1111-1111-1111",
                    }
                }
            }
        }
        result = PiiRedactor.redact_payload(deeply_nested)
        inner = result["level1"]["level2"]["level3"]
        assert "REDACTED_EMAIL_ADDRESS" in inner["contact"]
        assert "REDACTED_CREDIT_CARD" in inner["cc"]

    def test_pii_redactor_preserves_non_string_values(self):
        payload = {
            "name": "alice",
            "age": 30,
            "active": True,
            "score": 98.6,
            "null_val": None,
        }
        result = PiiRedactor.redact_payload(payload)
        assert result == payload

    def test_pii_redactor_handles_empty_string(self):
        result = PiiRedactor.redact_payload({"empty": ""})
        assert result["empty"] == ""

    def test_redact_email_in_mixed_content(self):
        result = PiiRedactor.redact_payload(
            {"note": "URGENT: reset password for admin@company.com immediately"}
        )
        assert "admin@company.com" not in result["note"]
        assert "URGENT" in result["note"]
        assert "REDACTED_EMAIL_ADDRESS" in result["note"]
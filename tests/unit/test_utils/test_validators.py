import pytest
from secureagentnet.utils.validators import (
    validate_agent_name,
    validate_uuid,
    validate_email,
    sanitize_command,
    validate_public_key,
    validate_jwt,
    validate_capability_name,
    validate_trust_score,
    validate_payload_size,
    validate_capability_level,
)


class TestValidators:
    def test_validate_agent_name_valid(self):
        assert validate_agent_name("agent-007") is True
        assert validate_agent_name("my_agent_name") is True
        assert validate_agent_name("a" * 64) is True
        assert validate_agent_name("ABC123") is True

    def test_validate_agent_name_too_short(self):
        assert validate_agent_name("ab") is False

    def test_validate_agent_name_too_long(self):
        assert validate_agent_name("a" * 65) is False

    def test_validate_agent_name_invalid_chars(self):
        assert validate_agent_name("agent name!") is False
        assert validate_agent_name("agent@name") is False
        assert validate_agent_name("agent.name") is False

    def test_validate_uuid_valid(self):
        assert validate_uuid("550e8400-e29b-41d4-a716-446655440000") is True

    def test_validate_uuid_invalid(self):
        assert validate_uuid("not-a-uuid") is False
        assert validate_uuid("") is False

    def test_validate_uuid_none(self):
        assert validate_uuid("") is False

    def test_validate_email_valid(self):
        assert validate_email("user@example.com") is True
        assert validate_email("first.last@company.co.uk") is True
        assert validate_email("user+tag@domain.org") is True

    def test_validate_email_invalid(self):
        assert validate_email("not-an-email") is False
        assert validate_email("user@") is False
        assert validate_email("@domain.com") is False
        assert validate_email("user@.com") is False

    def test_sanitize_command(self):
        result = sanitize_command("echo hello ; rm -rf /")
        assert "[SANITIZED]" in result
        assert "rm" not in result or "[SANITIZED]" in result

    def test_sanitize_command_shell_injection(self):
        result = sanitize_command("cat file | sh")
        assert "[SANITIZED]" in result

    def test_sanitize_command_backtick(self):
        result = sanitize_command("echo `rm -rf /`")
        assert "[SANITIZED]" in result

    def test_sanitize_command_var_substitution(self):
        result = sanitize_command("echo $(rm -rf /)")
        assert "[SANITIZED]" in result

    def test_sanitize_command_dev_redirect(self):
        result = sanitize_command("echo data > /dev/sda")
        assert "[SANITIZED]" in result

    def test_sanitize_command_benign(self):
        result = sanitize_command("python script.py --input /tmp/data.txt")
        assert result == "python script.py --input /tmp/data.txt"

    def test_validate_public_key_format(self):
        valid_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"
        assert validate_public_key(valid_key) is True

    def test_validate_public_key_invalid(self):
        assert validate_public_key("not-a-key") is False

    def test_validate_jwt_format(self):
        assert validate_jwt("header.payload.signature") is True
        assert validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature") is True

    def test_validate_jwt_invalid(self):
        assert validate_jwt("not-a-jwt") is False

    def test_validate_capability_name(self):
        assert validate_capability_name("read_file") is True
        assert validate_capability_name("execute_sql") is True

    def test_validate_capability_name_invalid(self):
        assert validate_capability_name("ReadFile") is False
        assert validate_capability_name("") is False

    def test_validate_trust_score(self):
        assert validate_trust_score(50.0) is True
        assert validate_trust_score(0.0) is True
        assert validate_trust_score(100.0) is True

    def test_validate_trust_score_invalid(self):
        assert validate_trust_score(-1.0) is False
        assert validate_trust_score(101.0) is False

    def test_validate_payload_size(self):
        assert validate_payload_size({"key": "value"}) is True
        huge = {"data": "x" * 2_000_000}
        assert validate_payload_size(huge) is False

    def test_validate_capability_level(self):
        for level in range(5):
            assert validate_capability_level(level) is True

    def test_validate_capability_level_invalid(self):
        assert validate_capability_level(-1) is False
        assert validate_capability_level(5) is False
        assert validate_capability_level(100) is False

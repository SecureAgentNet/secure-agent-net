import pytest
from secureagentnet.decide.pii_redactor import PiiRedactor


class TestPiiRedactor:
    def test_redact_email(self):
        payload = {"user_email": "john.doe@example.com"}
        result = PiiRedactor.redact_payload(payload)
        assert result["user_email"] == "[REDACTED_EMAIL_ADDRESS]"

    def test_redact_multiple_emails(self):
        payload = {
            "from": "alice@test.com",
            "to": "bob@test.org",
        }
        result = PiiRedactor.redact_payload(payload)
        assert result["from"] == "[REDACTED_EMAIL_ADDRESS]"
        assert result["to"] == "[REDACTED_EMAIL_ADDRESS]"

    def test_redact_phone(self):
        payload = {"phone": "212-555-1234"}
        result = PiiRedactor.redact_payload(payload)
        assert result["phone"] == "[REDACTED_PHONE_NUMBER]"

    def test_redact_phone_with_country_code(self):
        payload = {"phone": "+1 212-555-1234"}
        result = PiiRedactor.redact_payload(payload)
        assert "[REDACTED_PHONE_NUMBER]" in result["phone"]

    def test_redact_phone_parenthesized(self):
        payload = {"phone": "(212) 555-1234"}
        result = PiiRedactor.redact_payload(payload)
        assert "[REDACTED_PHONE_NUMBER]" in result["phone"]

    def test_redact_ssn(self):
        payload = {"ssn": "456-78-9123"}
        result = PiiRedactor.redact_payload(payload)
        assert result["ssn"] == "[REDACTED_US_SSN]"

    def test_redact_credit_card(self):
        payload = {"card": "4111-1111-1111-1111"}
        result = PiiRedactor.redact_payload(payload)
        assert result["card"] == "[REDACTED_CREDIT_CARD]"

    def test_redact_credit_card_spaces(self):
        payload = {"card": "4111 1111 1111 1111"}
        result = PiiRedactor.redact_payload(payload)
        assert result["card"] == "[REDACTED_CREDIT_CARD]"

    def test_redact_credit_card_continuous(self):
        payload = {"card": "4111111111111111"}
        result = PiiRedactor.redact_payload(payload)
        assert result["card"] == "[REDACTED_CREDIT_CARD]"

    def test_redact_nested_dict(self):
        payload = {
            "user": {
                "email": "nested@example.com",
                "profile": {
                    "phone": "212-987-6543",
                },
            }
        }
        result = PiiRedactor.redact_payload(payload)
        assert result["user"]["email"] == "[REDACTED_EMAIL_ADDRESS]"
        assert result["user"]["profile"]["phone"] == "[REDACTED_PHONE_NUMBER]"

    def test_redact_list(self):
        payload = {
            "recipients": ["alice@test.com", "bob@test.org"],
        }
        result = PiiRedactor.redact_payload(payload)
        assert result["recipients"][0] == "[REDACTED_EMAIL_ADDRESS]"
        assert result["recipients"][1] == "[REDACTED_EMAIL_ADDRESS]"

    def test_redact_list_with_dicts(self):
        payload = {
            "contacts": [
                {"email": "a@test.com", "name": "Alice"},
                {"email": "b@test.com", "name": "Bob"},
            ],
        }
        result = PiiRedactor.redact_payload(payload)
        assert result["contacts"][0]["email"] == "[REDACTED_EMAIL_ADDRESS]"
        assert result["contacts"][0]["name"] == "Alice"
        assert result["contacts"][1]["email"] == "[REDACTED_EMAIL_ADDRESS]"

    def test_no_pii_no_change(self):
        payload = {
            "action": "read_file",
            "path": "/tmp/data.txt",
            "encoding": "utf-8",
            "count": 42,
            "enabled": True,
        }
        result = PiiRedactor.redact_payload(payload)
        assert result == payload

    def test_empty_payload(self):
        assert PiiRedactor.redact_payload({}) == {}

    def test_mixed_types_no_pii(self):
        payload = {
            "string": "hello world",
            "int": 100,
            "float": 3.14,
            "bool": False,
            "none": None,
        }
        result = PiiRedactor.redact_payload(payload)
        assert result == payload

    def test_multiple_pii_types_in_one_string(self):
        payload = {
            "note": "Contact john@test.com or call 212-555-1234. SSN: 456-78-9123",
        }
        result = PiiRedactor.redact_payload(payload)
        assert "[REDACTED_EMAIL_ADDRESS]" in result["note"]
        assert "[REDACTED_PHONE_NUMBER]" in result["note"]
        assert "[REDACTED_US_SSN]" in result["note"]

    def test_redact_ip_address(self):
        payload = {"host": "192.168.1.100"}
        result = PiiRedactor.redact_payload(payload)
        assert result["host"] == "[REDACTED_IP_ADDRESS]"

    def test_presidio_init_failure_raises_error(self, monkeypatch):
        from secureagentnet.core.exceptions import PIIRedactionError
        monkeypatch.setattr(
            "secureagentnet.decide.pii_redactor._get_analyzer",
            lambda: (_ for _ in ()).throw(RuntimeError("Presidio unavailable")),
        )
        with pytest.raises(PIIRedactionError, match="Presidio unavailable"):
            PiiRedactor.redact_payload({"test": "data"})
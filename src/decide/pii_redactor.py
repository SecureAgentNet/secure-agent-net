import re
from typing import Dict, Any

class PiiRedactor:
    """
    Tier 2 Evaluation: Redacts common PII patterns before sending to the LLM.
    This is a very basic implementation for demonstration.
    """
    
    # Regex for common PII patterns
    PATTERNS = {
        "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b")
    }
    
    @classmethod
    def redact_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively traverses a dictionary and redacts PII from string values.
        """
        redacted_payload = {}
        for key, value in payload.items():
            if isinstance(value, str):
                redacted_payload[key] = cls._redact_string(value)
            elif isinstance(value, dict):
                redacted_payload[key] = cls.redact_payload(value)
            elif isinstance(value, list):
                redacted_payload[key] = [cls._redact_list_item(item) for item in value]
            else:
                redacted_payload[key] = value
        return redacted_payload

    @classmethod
    def _redact_list_item(cls, item: Any) -> Any:
        if isinstance(item, str):
            return cls._redact_string(item)
        if isinstance(item, dict):
            return cls.redact_payload(item)
        return item

    @classmethod
    def _redact_string(cls, text: str) -> str:
        for pii_type, pattern in cls.PATTERNS.items():
            text = pattern.sub(f"[REDACTED_{pii_type}]", text)
        return text

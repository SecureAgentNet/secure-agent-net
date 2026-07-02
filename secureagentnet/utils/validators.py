import re
from typing import Any, Dict, List, Optional
from uuid import UUID


AGENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,64}$")
PUBLIC_KEY_PATTERN = re.compile(r"^-----BEGIN PUBLIC KEY-----\n[\s\S]+?\n-----END PUBLIC KEY-----$")
JWT_PATTERN = re.compile(r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$")
CAPABILITY_NAME_PATTERN = re.compile(r"^[a-z][a-z_]{2,63}$")
URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def validate_agent_name(name: str) -> bool:
    return bool(AGENT_NAME_PATTERN.match(name))


def validate_public_key(key: str) -> bool:
    return bool(PUBLIC_KEY_PATTERN.match(key.strip()))


def validate_jwt(token: str) -> bool:
    return bool(JWT_PATTERN.match(token))


def validate_capability_name(name: str) -> bool:
    return bool(CAPABILITY_NAME_PATTERN.match(name))


def validate_uuid(uuid_str: str) -> bool:
    try:
        UUID(uuid_str)
        return True
    except (ValueError, AttributeError):
        return False


def validate_email(email: str) -> bool:
    pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    return bool(pattern.match(email))


def validate_trust_score(score: float) -> bool:
    return 0.0 <= score <= 100.0


def validate_payload_size(payload: Dict[str, Any], max_bytes: int = 1_000_000) -> bool:
    import json
    return len(json.dumps(payload).encode("utf-8")) <= max_bytes


def sanitize_command(command: str) -> str:
    dangerous_patterns = [
        r";\s*(rm|wget|curl|nc|bash|sh|mkfs|dd)",
        r"\$\(.*\)",
        r"`.*`",
        r"\|.*(sh|bash)",
        r">\s*/dev/",
        r"2>\s*&1",
    ]
    sanitized = command
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, "[SANITIZED]", sanitized, flags=re.IGNORECASE)
    return sanitized


def validate_capability_level(level: int) -> bool:
    return level in {0, 1, 2, 3, 4}

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


# Shell-injection patterns. Each is anchored so it matches the *construct*, not
# an incidental substring: the older `\|.*(sh|bash)` matched any "sh" anywhere
# after a pipe, so a benign `| rg 'Fulton Sheen'` was rewritten mid-string into
# a broken command. Word boundaries and bounded character classes keep each
# pattern to the thing it is actually named for.
DANGEROUS_COMMAND_PATTERNS = [
    (r";\s*(rm|wget|curl|nc|bash|sh|mkfs|dd)\b", "chained destructive/network command"),
    (r"\$\([^)]*\)", "command substitution $(...)"),
    (r"`[^`]*`", "command substitution with backticks"),
    (r"\|\s*(sh|bash|zsh|dash)\b", "pipe into a shell interpreter"),
    (r">\s*/dev/", "redirect to a device file"),
]
# `2>&1` was previously treated as dangerous. Redirecting stderr to stdout
# cannot escalate anything, and flagging it only produced false positives.


class CommandInspection:
    """The result of screening a command for shell-injection constructs."""

    def __init__(self, original: str, findings: List[str], sanitized: str):
        self.original = original
        self.findings = findings
        self.sanitized = sanitized

    @property
    def safe(self) -> bool:
        return not self.findings

    def __bool__(self) -> bool:
        return self.safe


def inspect_command(command: str) -> CommandInspection:
    """Screen a command without executing it.

    Returns the constructs found so the caller can *reject* the request. Callers
    must not run ``sanitized`` in place of the original: substituting a rewritten
    string would execute something the operator never submitted and the audit
    trail never recorded.
    """
    findings: List[str] = []
    sanitized = command
    for pattern, description in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, sanitized, flags=re.IGNORECASE):
            findings.append(description)
            sanitized = re.sub(pattern, "[SANITIZED]", sanitized, flags=re.IGNORECASE)
    return CommandInspection(command, findings, sanitized)


def sanitize_command(command: str) -> str:
    """Redact shell-injection constructs from a command string.

    Retained for callers that only need a display/log-safe rendering. Anything
    deciding whether to *run* a command should use :func:`inspect_command` and
    block on findings rather than executing the redacted text.
    """
    return inspect_command(command).sanitized


def validate_capability_level(level: int) -> bool:
    return level in {0, 1, 2, 3, 4}

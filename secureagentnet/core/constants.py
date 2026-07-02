from enum import Enum


class PipelinePhase(str, Enum):
    IDENTIFY = "IDENTIFY"
    TRACK = "TRACK"
    CONTAIN = "CONTAIN"
    DECIDE = "DECIDE"


class AgentStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    ROGUE = "rogue"


class CapabilityLevel(int, Enum):
    READ_ONLY = 0
    LIMITED_WRITE = 1
    API_CALLS = 2
    CODE_EXECUTION = 3
    SYSTEM_COMMANDS = 4


class EventSeverity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class FinalDecision(str, Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


DEFAULT_RATE_LIMIT = 100
DEFAULT_CONTAINER_MEMORY_MB = 512
DEFAULT_CONTAINER_CPU_QUOTA = 100000
DEFAULT_CONTAINER_TIMEOUT_S = 60
DEFAULT_AUTH_TOKEN_EXPIRY_S = 3600
DEFAULT_KILL_SWITCH_DENIAL_THRESHOLD = 3
DEFAULT_KILL_SWITCH_BLOCK_DURATION_S = 900
CIRCUIT_BREAKER_FAIL_MAX = 5
CIRCUIT_BREAKER_TIMEOUT_S = 60

ALLOWED_AGENT_TYPES = {"LangChain", "AutoGen", "CrewAI", "Custom"}

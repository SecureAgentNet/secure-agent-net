class SecureAgentNetError(Exception):
    pass


class AuthenticationError(SecureAgentNetError):
    pass


class AuthorizationError(SecureAgentNetError):
    pass


class AgentNotFoundError(SecureAgentNetError):
    pass


class AgentSuspendedError(SecureAgentNetError):
    pass


class ContainerProvisioningError(SecureAgentNetError):
    pass


class ContainerTimeoutError(SecureAgentNetError):
    pass


class ContainerEscapeAttemptError(SecureAgentNetError):
    pass


class RuleFilterDeniedError(SecureAgentNetError):
    pass


class LLMEvaluationError(SecureAgentNetError):
    pass


class PIIRedactionError(SecureAgentNetError):
    pass


class CircuitBreakerOpenError(SecureAgentNetError):
    pass


class KillSwitchActiveError(SecureAgentNetError):
    pass


class VaultConnectionError(SecureAgentNetError):
    pass


class DatabaseConnectionError(SecureAgentNetError):
    pass


class IntentCapsuleExpiredError(SecureAgentNetError):
    pass


class GoalHijackingDetectedError(SecureAgentNetError):
    pass


class InvalidConfigurationError(SecureAgentNetError):
    pass


class PipelineBlockedError(SecureAgentNetError):
    """Raised when the pipeline blocks an action (carries block details)."""
    def __init__(self, reason: str, evaluated_by: str = "DECIDE", risk_score: float = 1.0, metadata: dict = None):
        self.reason = reason
        self.evaluated_by = evaluated_by
        self.risk_score = risk_score
        self.metadata = metadata or {}
        super().__init__(reason)

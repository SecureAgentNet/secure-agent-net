import logging
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta, timezone

from src.core.exceptions import IntentCapsuleExpiredError, GoalHijackingDetectedError

logger = logging.getLogger("SecureAgentNet.Decide.IntentCapsule")


class IntentCapsule:
    def __init__(
        self,
        user_id: str,
        original_goal: str,
        approved_actions: Optional[List[str]] = None,
        forbidden_actions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        expires_in_minutes: int = 60,
        agent_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        active: bool = True,
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id = agent_id
        self.user_id = user_id
        self.original_goal = original_goal
        self.approved_actions = approved_actions or []
        self.forbidden_actions = forbidden_actions or []
        self.created_at = self._as_aware(created_at) or datetime.now(timezone.utc)
        self.expires_at = self._as_aware(expires_at) or (
            self.created_at + timedelta(minutes=expires_in_minutes))
        self.active = active

    @staticmethod
    def _as_aware(val) -> Optional[datetime]:
        """Coerce strings / naive datetimes (e.g. read back from the DB) to UTC-aware."""
        if val is None:
            return None
        if isinstance(val, str):
            try:
                val = datetime.fromisoformat(val)
            except (ValueError, TypeError):
                return None
        if isinstance(val, datetime) and val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def check_expired(self):
        if self.is_expired():
            raise IntentCapsuleExpiredError(
                f"Intent capsule {self.session_id} expired at {self.expires_at}"
            )

    def is_action_allowed(self, action: str) -> bool:
        self.check_expired()
        if not self.active:
            return False
        if action in self.forbidden_actions:
            return False
        # A "*" entry is a wildcard mandate — every (non-forbidden) action is sanctioned.
        if "*" in self.approved_actions:
            return True
        if self.approved_actions and action not in self.approved_actions:
            return False
        return True

    def detect_goal_hijack(self, proposed_action: str, proposed_intent: str) -> bool:
        self.check_expired()
        if proposed_action in self.forbidden_actions:
            return True
        hijack_phrases = [
            "ignore previous", "ignore all", "override", "admin mode",
            "developer mode", "sudo", "privileged", "bypass",
        ]
        intent_lower = proposed_intent.lower()
        for phrase in hijack_phrases:
            if phrase in intent_lower:
                logger.warning(f"Goal hijack detected: '{phrase}' in intent")
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "original_goal": self.original_goal,
            "approved_actions": self.approved_actions,
            "forbidden_actions": self.forbidden_actions,
            "created_at": self.created_at.isoformat() if hasattr(self.created_at, "isoformat") else self.created_at,
            "expires_at": self.expires_at.isoformat() if hasattr(self.expires_at, "isoformat") else self.expires_at,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IntentCapsule":
        return cls(
            session_id=str(d["session_id"]),
            agent_id=str(d["agent_id"]) if d.get("agent_id") else None,
            user_id=d.get("user_id", "system"),
            original_goal=d["original_goal"],
            approved_actions=list(d.get("approved_actions") or []),
            forbidden_actions=list(d.get("forbidden_actions") or []),
            created_at=d.get("created_at"),
            expires_at=d.get("expires_at"),
            active=bool(d.get("active", True)),
        )

    def deactivate(self):
        self.active = False
        logger.info(f"Intent capsule {self.session_id} deactivated.")


class IntentCapsuleManager:
    _capsules: Dict[str, IntentCapsule] = {}

    @classmethod
    def create_capsule(cls, **kwargs) -> IntentCapsule:
        capsule = IntentCapsule(**kwargs)
        cls._capsules[capsule.session_id] = capsule
        logger.info(f"Intent capsule created: {capsule.session_id}")
        return capsule

    @classmethod
    def get_capsule(cls, session_id: str) -> Optional[IntentCapsule]:
        capsule = cls._capsules.get(session_id)
        if capsule and capsule.is_expired():
            capsule.active = False
            return None
        return capsule

    @classmethod
    def remove_expired(cls):
        now = datetime.now(timezone.utc)
        expired = [sid for sid, cap in cls._capsules.items() if cap.expires_at < now]
        for sid in expired:
            cls._capsules[sid].active = False
            del cls._capsules[sid]
        if expired:
            logger.info(f"Removed {len(expired)} expired intent capsules.")


# Actions no agent is ever auto-cleared to perform; an explicit commission can
# still widen this, but the default mandate always forbids them.
DEFAULT_FORBIDDEN_ACTIONS = ["delete_database", "format_drive", "exfiltrate_keys"]
DEFAULT_MANDATE_EXPIRY_MINUTES = 7 * 24 * 60  # 7 days — a commission, not a session


class MandateRegistry:
    """Durable, agent-bound mandates — the anchor goal-hijacking is checked against.

    A *mandate* is what an agent was commissioned to do: its ``original_goal``
    plus the actions it is (and is not) sanctioned to take. Unlike the in-memory
    ``IntentCapsuleManager``, this is persisted in the ``intent_capsules`` table
    and looked up by ``agent_id`` so a commission survives across processes.

    Policy (chosen for this build): the pipeline is **fail-closed** — an agent
    with no mandate cannot act. To keep that workable, ``get_active`` lazily
    auto-provisions a default mandate (from the agent's granted capabilities)
    for any agent that exists in the registry but has not been commissioned yet;
    a truly unknown agent gets ``None`` and is blocked.
    """

    @classmethod
    def get_active(cls, agent_id: str) -> Optional[IntentCapsule]:
        from src.database.repositories import MandateRepository

        record = MandateRepository.get_active_for_agent(agent_id)
        if record:
            return IntentCapsule.from_dict(record)

        # No mandate yet — auto-provision one for a known agent, else fail-closed.
        from src.identify.identity_registry import IdentityRegistry
        agent = IdentityRegistry.get_agent(agent_id)
        if not agent:
            return None
        return cls._provision_default(agent)

    @classmethod
    def _provision_default(cls, agent: Dict[str, Any]) -> IntentCapsule:
        """Build and persist a default mandate from an agent's capabilities."""
        capabilities = agent.get("capabilities", {}) or {}
        is_admin = capabilities.get("*") or capabilities.get("level") == "admin" \
            or "*" in (capabilities.get("actions") or [])
        if is_admin:
            approved = ["*"]
        else:
            approved = [k for k, v in capabilities.items()
                        if v is True and k not in ("level", "actions")]
            approved = approved or ["*"]  # capability gate still applies at IDENTIFY

        goal = agent.get("description") or (
            f"Operate as a {agent.get('type', 'Custom')} agent strictly within its "
            f"granted capabilities ({', '.join(approved)})."
        )
        capsule = cls.commission(
            agent_id=agent["agent_id"],
            original_goal=goal,
            approved_actions=approved,
            forbidden_actions=list(DEFAULT_FORBIDDEN_ACTIONS),
            user_id=agent.get("created_by", "system"),
            expires_in_minutes=DEFAULT_MANDATE_EXPIRY_MINUTES,
        )
        logger.info("Auto-provisioned default mandate for agent %s", agent["agent_id"])
        return capsule

    @classmethod
    def commission(
        cls,
        agent_id: str,
        original_goal: str,
        approved_actions: Optional[List[str]] = None,
        forbidden_actions: Optional[List[str]] = None,
        user_id: str = "operator",
        expires_in_minutes: int = DEFAULT_MANDATE_EXPIRY_MINUTES,
    ) -> IntentCapsule:
        """Commission (or re-commission) an agent. Retires any prior mandate."""
        from src.database.repositories import MandateRepository

        MandateRepository.deactivate_for_agent(agent_id)
        capsule = IntentCapsule(
            agent_id=agent_id,
            user_id=user_id,
            original_goal=original_goal,
            approved_actions=approved_actions or ["*"],
            forbidden_actions=forbidden_actions if forbidden_actions is not None
            else list(DEFAULT_FORBIDDEN_ACTIONS),
            expires_in_minutes=expires_in_minutes,
        )
        MandateRepository.save(capsule.to_dict())
        logger.info("Commissioned agent %s: %s", agent_id, original_goal[:80])
        return capsule

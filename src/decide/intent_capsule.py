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
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.user_id = user_id
        self.original_goal = original_goal
        self.approved_actions = approved_actions or []
        self.forbidden_actions = forbidden_actions or []
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = self.created_at + timedelta(minutes=expires_in_minutes)
        self.active = True

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
            "user_id": self.user_id,
            "original_goal": self.original_goal,
            "approved_actions": self.approved_actions,
            "forbidden_actions": self.forbidden_actions,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "active": self.active,
        }

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

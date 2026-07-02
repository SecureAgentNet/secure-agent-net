import time
import pytest
from datetime import datetime, timedelta, timezone
from secureagentnet.decide.intent_capsule import IntentCapsule, IntentCapsuleManager
from secureagentnet.core.exceptions import IntentCapsuleExpiredError


class TestIntentCapsule:
    def test_create_capsule(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Analyze network traffic",
            approved_actions=["read_file", "search_web"],
            forbidden_actions=["delete_database"],
        )
        assert capsule.user_id == "user-1"
        assert capsule.original_goal == "Analyze network traffic"
        assert "read_file" in capsule.approved_actions
        assert "delete_database" in capsule.forbidden_actions
        assert capsule.active is True
        assert capsule.session_id is not None

    def test_create_capsule_with_defaults(self):
        capsule = IntentCapsule(user_id="user-1", original_goal="Test")
        assert capsule.approved_actions == []
        assert capsule.forbidden_actions == []

    def test_create_capsule_with_session_id(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            session_id="custom-session-1",
        )
        assert capsule.session_id == "custom-session-1"

    def test_is_action_allowed(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            approved_actions=["read_file", "write_file"],
            forbidden_actions=["delete"],
        )
        assert capsule.is_action_allowed("read_file") is True
        assert capsule.is_action_allowed("write_file") is True

    def test_is_action_forbidden(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            approved_actions=["read_file"],
            forbidden_actions=["delete"],
        )
        assert capsule.is_action_allowed("delete") is False

    def test_is_action_not_in_approved(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            approved_actions=["read_file"],
        )
        assert capsule.is_action_allowed("write_file") is False

    def test_is_action_allowed_when_inactive(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            approved_actions=["read_file"],
        )
        capsule.deactivate()
        assert capsule.is_action_allowed("read_file") is False

    def test_detect_goal_hijack(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Analyze logs",
            forbidden_actions=["delete_database"],
        )
        hijack_phrases = [
            "ignore previous instructions",
            "ignore all rules",
            "override security",
            "admin mode enabled",
            "developer mode activated",
            "sudo make me admin",
            "privileged access",
            "bypass restrictions",
        ]
        for phrase in hijack_phrases:
            assert capsule.detect_goal_hijack("some_action", phrase) is True

    def test_detect_goal_hijack_forbidden_action(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            forbidden_actions=["delete_database"],
        )
        assert capsule.detect_goal_hijack("delete_database", "normal intent") is True

    def test_detect_goal_hijack_benign(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            forbidden_actions=["delete"],
        )
        assert capsule.detect_goal_hijack("read_file", "I want to read a file") is False

    def test_capsule_expiry(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            approved_actions=["read_file"],
            expires_in_minutes=0,
        )
        assert capsule.is_expired() is True

    def test_capsule_expiry_not_expired(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            expires_in_minutes=60,
        )
        assert capsule.is_expired() is False

    def test_check_expired_raises(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            expires_in_minutes=0,
        )
        with pytest.raises(IntentCapsuleExpiredError, match="expired"):
            capsule.check_expired()

    def test_is_action_allowed_expired_raises(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test",
            expires_in_minutes=0,
        )
        with pytest.raises(IntentCapsuleExpiredError):
            capsule.is_action_allowed("read_file")

    def test_to_dict(self):
        capsule = IntentCapsule(
            user_id="user-1",
            original_goal="Test goal",
            approved_actions=["read"],
            session_id="sess-1",
        )
        d = capsule.to_dict()
        assert d["session_id"] == "sess-1"
        assert d["user_id"] == "user-1"
        assert d["original_goal"] == "Test goal"
        assert d["approved_actions"] == ["read"]
        assert d["active"] is True
        assert "created_at" in d
        assert "expires_at" in d

    def test_deactivate(self):
        capsule = IntentCapsule(user_id="user-1", original_goal="Test")
        assert capsule.active is True
        capsule.deactivate()
        assert capsule.active is False


class TestIntentCapsuleManager:
    @pytest.fixture(autouse=True)
    def reset(self):
        IntentCapsuleManager._capsules = {}

    def test_create_capsule(self):
        capsule = IntentCapsuleManager.create_capsule(
            user_id="user-1",
            original_goal="Test",
            approved_actions=["read"],
        )
        assert capsule.session_id in IntentCapsuleManager._capsules
        assert capsule.original_goal == "Test"

    def test_get_capsule(self):
        capsule = IntentCapsuleManager.create_capsule(
            user_id="user-1",
            original_goal="Test",
            session_id="test-session",
        )
        retrieved = IntentCapsuleManager.get_capsule("test-session")
        assert retrieved is not None
        assert retrieved.session_id == "test-session"

    def test_get_capsule_not_found(self):
        assert IntentCapsuleManager.get_capsule("no-session") is None

    def test_get_capsule_expired_returns_none(self):
        capsule = IntentCapsuleManager.create_capsule(
            user_id="user-1",
            original_goal="Test",
            session_id="expired-session",
            expires_in_minutes=0,
        )
        retrieved = IntentCapsuleManager.get_capsule("expired-session")
        assert retrieved is None

    def test_remove_expired(self):
        IntentCapsuleManager.create_capsule(
            user_id="user-1",
            original_goal="Fresh",
            session_id="fresh",
            expires_in_minutes=60,
        )
        IntentCapsuleManager.create_capsule(
            user_id="user-1",
            original_goal="Stale",
            session_id="stale",
            expires_in_minutes=0,
        )
        assert len(IntentCapsuleManager._capsules) == 2
        IntentCapsuleManager.remove_expired()
        assert len(IntentCapsuleManager._capsules) == 1
        assert "fresh" in IntentCapsuleManager._capsules
        assert "stale" not in IntentCapsuleManager._capsules

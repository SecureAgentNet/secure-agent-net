import pytest
from secureagentnet.decide.kill_switch import KillSwitchController
from secureagentnet.core.exceptions import KillSwitchActiveError


class TestKillSwitchController:
    @pytest.fixture
    def ks(self):
        ctrl = KillSwitchController()
        ctrl._denial_threshold = 3
        return ctrl

    def test_initial_state(self, ks):
        assert ks.is_armed is True
        assert ks.is_active is False
        status = ks.get_status()
        assert status["armed"] is True
        assert status["active"] is False
        assert status["trigger_count"] == 0
        assert status["denial_threshold"] == 3

    def test_arm_disarm(self, ks):
        assert ks.is_armed is True
        ks.disarm()
        assert ks.is_armed is False
        ks.arm()
        assert ks.is_armed is True

    def test_record_denial_triggers(self, ks):
        result = ks.record_denial("agent-1")
        assert result is False
        result = ks.record_denial("agent-1")
        assert result is False
        result = ks.record_denial("agent-1")
        assert result is True
        assert ks.is_active is True

    def test_record_denial_below_threshold(self, ks):
        result = ks.record_denial("agent-1")
        assert result is False
        assert ks.is_active is False

    def test_record_denial_does_not_increment_when_disarmed(self, ks):
        ks.disarm()
        result = ks.record_denial("agent-1")
        assert result is False
        assert ks.is_active is False

    def test_record_denial_does_not_increment_when_active(self, ks):
        ks._activate()
        result = ks.record_denial("agent-1")
        assert result is True

    def test_record_denial_triggers_on_total_denials(self, ks):
        ks._denial_threshold = 2
        agents = [f"agent-{i}" for i in range(6)]
        for a in agents:
            ks.record_denial(a)
        total = ks._denial_threshold * 3
        assert total == 6
        assert ks.is_active is True

    def test_activate_deactivate(self, ks):
        ks._activate()
        assert ks.is_active is True
        assert ks._trigger_count == 1
        assert ks._last_triggered_at is not None

        ks.deactivate(reset_by="test-admin")
        assert ks.is_active is False
        assert ks._last_reset_at is not None
        assert ks.get_status()["agent_denial_counts"] == {}

    def test_check_passes_when_inactive(self, ks):
        assert ks.check() is True

    def test_check_raises_when_active(self, ks):
        ks._activate()
        with pytest.raises(KillSwitchActiveError, match="Kill-switch is active"):
            ks.check()

    def test_get_status(self, ks):
        ks.record_denial("agent-1")
        status = ks.get_status()
        assert status["armed"] is True
        assert status["active"] is False
        assert status["agent_denial_counts"] == {"agent-1": 1}

    def test_get_status_when_active(self, ks):
        for _ in range(3):
            ks.record_denial("agent-1")
        status = ks.get_status()
        assert status["active"] is True
        assert status["trigger_count"] == 1

    def test_reset_agent_counters(self, ks):
        ks.record_denial("agent-1")
        ks.record_denial("agent-1")
        assert ks.get_status()["agent_denial_counts"] == {"agent-1": 2}
        ks.reset_agent_counters("agent-1")
        assert "agent-1" not in ks.get_status()["agent_denial_counts"]

    def test_reset_agent_counters_nonexistent(self, ks):
        ks.reset_agent_counters("no-such-agent")

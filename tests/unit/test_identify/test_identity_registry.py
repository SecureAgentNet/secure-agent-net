import pytest
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.core.constants import AgentStatus
from secureagentnet.core.exceptions import AgentNotFoundError, AgentSuspendedError


class TestIdentityRegistry:
    def test_register_agent(self):
        agent_data = {
            "name": "alpha-agent",
            "type": "LangChain",
            "description": "Alpha test agent",
            "public_key": "pk-alpha-001",
            "capabilities": {"search": True},
            "metadata": {"env": "test"},
            "created_by": "admin",
        }
        agent = IdentityRegistry.register_agent(agent_data)
        assert agent["name"] == "alpha-agent"
        assert agent["type"] == "LangChain"
        assert agent["status"] == AgentStatus.ACTIVE.value
        assert agent["trust_score"] == 50.0
        assert "agent_id" in agent
        assert agent["created_by"] == "admin"

    def test_get_agent(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        retrieved = IdentityRegistry.get_agent(agent_id)
        assert retrieved is not None
        assert retrieved["name"] == sample_agent["name"]

    def test_get_agent_not_found(self):
        assert IdentityRegistry.get_agent("nonexistent-id") is None

    def test_get_agent_by_name(self, sample_agent):
        agent = IdentityRegistry.get_agent_by_name("test-agent-alpha")
        assert agent is not None
        assert agent["agent_id"] == sample_agent["agent_id"]

    def test_get_agent_by_name_not_found(self):
        assert IdentityRegistry.get_agent_by_name("no-such-agent") is None

    def test_list_agents_filter_by_status(self):
        a1 = IdentityRegistry.register_agent({"name": "agent-active"})
        a2 = IdentityRegistry.register_agent({"name": "agent-suspended"})
        a3 = IdentityRegistry.register_agent({"name": "agent-revoked"})
        IdentityRegistry.suspend_agent(a2["agent_id"])
        IdentityRegistry.revoke_agent(a3["agent_id"])

        active = IdentityRegistry.list_agents(status=AgentStatus.ACTIVE.value)
        assert len(active) == 1
        assert active[0]["name"] == "agent-active"

        suspended = IdentityRegistry.list_agents(status=AgentStatus.SUSPENDED.value)
        assert len(suspended) == 1
        assert suspended[0]["name"] == "agent-suspended"

    def test_list_agents_filter_by_type(self):
        IdentityRegistry.register_agent({"name": "agent-lc", "type": "LangChain"})
        IdentityRegistry.register_agent({"name": "agent-custom", "type": "Custom"})
        lc_agents = IdentityRegistry.list_agents(agent_type="LangChain")
        assert len(lc_agents) == 1
        assert lc_agents[0]["type"] == "LangChain"

    def test_update_agent(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        updated = IdentityRegistry.update_agent(agent_id, {"description": "Updated description"})
        assert updated["description"] == "Updated description"

    def test_update_agent_not_found(self):
        with pytest.raises(AgentNotFoundError):
            IdentityRegistry.update_agent("bad-id", {"name": "new"})

    def test_update_trust_score(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        new_score = IdentityRegistry.update_trust_score(agent_id, 10.0)
        assert new_score == 60.0

    def test_update_trust_score_clamps_minimum(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        new_score = IdentityRegistry.update_trust_score(agent_id, -200.0)
        assert new_score == 0.0

    def test_update_trust_score_clamps_maximum(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        new_score = IdentityRegistry.update_trust_score(agent_id, 200.0)
        assert new_score == 100.0

    def test_update_trust_score_not_found(self):
        with pytest.raises(AgentNotFoundError):
            IdentityRegistry.update_trust_score("bad-id", 5.0)

    def test_revoke_agent(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        result = IdentityRegistry.revoke_agent(agent_id)
        assert result is True
        agent = IdentityRegistry.get_agent(agent_id)
        assert agent["status"] == AgentStatus.REVOKED.value

    def test_revoke_agent_not_found(self):
        with pytest.raises(AgentNotFoundError):
            IdentityRegistry.revoke_agent("bad-id")

    def test_suspend_agent(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        result = IdentityRegistry.suspend_agent(agent_id)
        assert result is True
        agent = IdentityRegistry.get_agent(agent_id)
        assert agent["status"] == AgentStatus.SUSPENDED.value

    def test_suspend_agent_not_found(self):
        with pytest.raises(AgentNotFoundError):
            IdentityRegistry.suspend_agent("bad-id")

    def test_mark_rogue(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        result = IdentityRegistry.mark_rogue(agent_id)
        assert result is True
        agent = IdentityRegistry.get_agent(agent_id)
        assert agent["status"] == AgentStatus.ROGUE.value
        assert agent["trust_score"] == 0.0

    def test_mark_rogue_not_found(self):
        with pytest.raises(AgentNotFoundError):
            IdentityRegistry.mark_rogue("bad-id")

    def test_check_agent_active_returns_true(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        assert IdentityRegistry.check_agent_active(agent_id) is True

    def test_check_agent_active_not_found(self):
        with pytest.raises(AgentNotFoundError):
            IdentityRegistry.check_agent_active("bad-id")

    def test_check_agent_active_raises_for_suspended(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        IdentityRegistry.suspend_agent(agent_id)
        with pytest.raises(AgentSuspendedError, match="suspended"):
            IdentityRegistry.check_agent_active(agent_id)

    def test_check_agent_active_raises_for_revoked(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        IdentityRegistry.revoke_agent(agent_id)
        with pytest.raises(AgentSuspendedError, match="revoked"):
            IdentityRegistry.check_agent_active(agent_id)

    def test_check_agent_active_raises_for_rogue(self, sample_agent):
        agent_id = sample_agent["agent_id"]
        IdentityRegistry.mark_rogue(agent_id)
        with pytest.raises(AgentSuspendedError, match="rogue"):
            IdentityRegistry.check_agent_active(agent_id)

    def test_get_active_count(self, sample_agent):
        a2 = IdentityRegistry.register_agent({"name": "second"})
        assert IdentityRegistry.get_active_count() == 2
        IdentityRegistry.suspend_agent(a2["agent_id"])
        assert IdentityRegistry.get_active_count() == 1

    def test_get_total_count(self, sample_agent):
        IdentityRegistry.register_agent({"name": "second"})
        IdentityRegistry.register_agent({"name": "third"})
        assert IdentityRegistry.get_total_count() == 3

    def test_register_agent_defaults(self):
        agent = IdentityRegistry.register_agent({})
        assert agent["name"] == "unknown"
        assert agent["type"] == "Custom"
        assert agent["description"] == ""
        assert agent["public_key"] == ""

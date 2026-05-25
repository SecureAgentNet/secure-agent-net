from typing import List, Dict, Optional
import logging

logger = logging.getLogger("SecureAgentNet.Identify")

_SEED_CAPABILITIES: Dict[str, List[str]] = {
    "agent-007": ["read_file", "execute_sql", "search_web"],
    "agent-rogue": ["search_web"],
}


class CapabilityProfiler:

    @classmethod
    def is_authorized(cls, agent_id: str, action_name: str) -> bool:
        from src.identify.identity_registry import IdentityRegistry

        agent = IdentityRegistry.get_agent(agent_id)
        if not agent:
            seed_caps = _SEED_CAPABILITIES.get(agent_id, [])
            if seed_caps:
                authorized = action_name in seed_caps
                if authorized:
                    logger.debug("Capability '%s' authorized for seed agent %s.", action_name, agent_id)
                else:
                    logger.warning("Capability '%s' DENIED for seed agent %s.", action_name, agent_id)
                return authorized
            return False

        capabilities = agent.get("capabilities", {})
        if not isinstance(capabilities, dict):
            capabilities = {}

        if action_name in capabilities:
            enabled = capabilities[action_name]
            if enabled or enabled is None:
                logger.debug("Capability '%s' authorized for agent %s.", action_name, agent_id)
                return True

        if capabilities.get("*") or capabilities.get("level") == "admin":
            logger.debug("Wildcard/admin capability grants '%s' for agent %s.", action_name, agent_id)
            return True

        logger.warning("Capability '%s' DENIED for agent %s.", action_name, agent_id)
        return False

    @classmethod
    def add_capability(cls, agent_id: str, action_name: str):
        from src.identify.identity_registry import IdentityRegistry

        agent = IdentityRegistry.get_agent(agent_id)
        if not agent:
            if agent_id not in _SEED_CAPABILITIES:
                _SEED_CAPABILITIES[agent_id] = []
            if action_name not in _SEED_CAPABILITIES[agent_id]:
                _SEED_CAPABILITIES[agent_id].append(action_name)
            return

        capabilities = dict(agent.get("capabilities", {}))
        capabilities[action_name] = True
        IdentityRegistry.update_agent(agent_id, {"capabilities": capabilities})
        logger.info("Granted '%s' to agent %s.", action_name, agent_id)

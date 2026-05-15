from typing import List, Dict
import logging

logger = logging.getLogger("SecureAgentNet.Identify")

class CapabilityProfiler:
    """
    Enforces Least-Privilege by ensuring an agent is explicitly 
    authorized to use the requested tool/capability.
    """
    
    # Mocking the database for now. 
    # Format: {agent_id: [allowed_capabilities]}
    _mock_db: Dict[str, List[str]] = {
        "agent-007": ["read_file", "execute_sql", "search_web"],
        "agent-rogue": ["search_web"]
    }
    
    @classmethod
    def is_authorized(cls, agent_id: str, action_name: str) -> bool:
        """
        Checks if the agent has the specific capability whitelisted.
        """
        allowed_actions = cls._mock_db.get(agent_id, [])
        
        if action_name in allowed_actions:
            logger.debug(f"Capability '{action_name}' authorized for agent {agent_id}.")
            return True
            
        logger.warning(f"Capability '{action_name}' DENIED for agent {agent_id}. Not in whitelist.")
        return False
        
    @classmethod
    def add_capability(cls, agent_id: str, action_name: str):
        """Grants a new capability to an agent (Admin only function)."""
        if agent_id not in cls._mock_db:
            cls._mock_db[agent_id] = []
        if action_name not in cls._mock_db[agent_id]:
            cls._mock_db[agent_id].append(action_name)
            logger.info(f"Granted '{action_name}' to agent {agent_id}.")

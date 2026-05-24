from typing import List, Dict
import logging
from src.utils.persistence import PersistenceStore

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
    _loaded: bool = False

    @classmethod
    def _persist(cls):
        PersistenceStore.save("capability_profiler", cls._mock_db)

    @classmethod
    def _load(cls):
        data = PersistenceStore.load("capability_profiler", None)
        if data is not None:
            cls._mock_db = data

    @classmethod
    def _ensure_loaded(cls):
        if not cls._loaded:
            cls._load()
            cls._loaded = True

    @classmethod
    def is_authorized(cls, agent_id: str, action_name: str) -> bool:
        cls._ensure_loaded()
        allowed_actions = cls._mock_db.get(agent_id, [])
        
        if action_name in allowed_actions:
            logger.debug(f"Capability '{action_name}' authorized for agent {agent_id}.")
            return True
            
        logger.warning(f"Capability '{action_name}' DENIED for agent {agent_id}. Not in whitelist.")
        return False
        
    @classmethod
    def add_capability(cls, agent_id: str, action_name: str):
        cls._ensure_loaded()
        if agent_id not in cls._mock_db:
            cls._mock_db[agent_id] = []
        if action_name not in cls._mock_db[agent_id]:
            cls._mock_db[agent_id].append(action_name)
            cls._persist()
            logger.info(f"Granted '{action_name}' to agent {agent_id}.")

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from secureagentnet.core.constants import AgentStatus
from secureagentnet.core.exceptions import AgentNotFoundError, AgentSuspendedError
from secureagentnet.database.repositories import AgentRepository

logger = logging.getLogger("SecureAgentNet.Identify.Registry")


class IdentityRegistry:
    _agents: Dict[str, Dict[str, Any]] = {}
    _initialized = False

    @classmethod
    def _persist(cls):
        AgentRepository.save_all(cls._agents)

    @classmethod
    def _load(cls):
        cls._agents = AgentRepository.load_all()

    @classmethod
    def initialize(cls):
        if not cls._initialized:
            cls._agents = {}
            cls._load()
            cls._initialized = True
            logger.info("IdentityRegistry initialized.")

    @classmethod
    def register_agent(cls, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        import uuid
        agent_id = str(uuid.uuid4())
        agent = {
            "agent_id": agent_id,
            "name": agent_data.get("name", "unknown"),
            "type": agent_data.get("type", "Custom"),
            "description": agent_data.get("description", ""),
            "public_key": agent_data.get("public_key", ""),
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "last_seen": None,
            "trust_score": 50.0,
            "status": AgentStatus.ACTIVE.value,
            "capabilities": agent_data.get("capabilities", {}),
            "metadata": agent_data.get("metadata", {}),
            "created_by": agent_data.get("created_by", "system"),
        }
        cls._agents[agent_id] = agent
        cls._persist()
        cls._issue_manifest(agent)
        logger.info(f"Agent registered: {agent_id} ({agent['name']})")
        return agent

    @classmethod
    def _issue_manifest(cls, agent: Dict[str, Any]):
        """Sign a trust-chain manifest for a newly registered agent (Deliverable 3).

        Bind the agent's identity, key and capabilities under the SAN root authority
        so its actions can later be verified back to the trust anchor. Guarded so a
        signing hiccup never blocks registration.
        """
        try:
            from secureagentnet.identify.trust_chain import TrustChainService
            signed = TrustChainService.issue(agent)
            meta = agent.setdefault("metadata", {})
            meta["manifest_fingerprint"] = signed.manifest.fingerprint()
            meta["manifest_issuer"] = signed.issuer_fingerprint
            cls._persist()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(f"Could not issue trust manifest for {agent.get('agent_id')}: {exc}")

    @classmethod
    def get_agent(cls, agent_id: str) -> Optional[Dict[str, Any]]:
        return cls._agents.get(agent_id)

    @classmethod
    def get_agent_by_name(cls, name: str) -> Optional[Dict[str, Any]]:
        for agent in cls._agents.values():
            if agent["name"] == name:
                return agent
        return None

    @classmethod
    def get_agent_by_public_key(cls, public_key: str) -> Optional[Dict[str, Any]]:
        for agent in cls._agents.values():
            if agent["public_key"] == public_key:
                return agent
        return None

    @classmethod
    def list_agents(cls, status: Optional[str] = None, agent_type: Optional[str] = None) -> List[Dict[str, Any]]:
        agents = list(cls._agents.values())
        if status:
            agents = [a for a in agents if a["status"] == status]
        if agent_type:
            agents = [a for a in agents if a["type"] == agent_type]
        return agents

    @classmethod
    def update_agent(cls, agent_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        if agent_id not in cls._agents:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
        cls._agents[agent_id].update(updates)
        cls._persist()
        if "status" in updates:
            logger.warning(f"Agent {agent_id} status changed to {updates['status']}")
        # A change to the agent's key or capabilities invalidates its signed
        # manifest — re-issue so the trust chain reflects the new authorization.
        if any(k in updates for k in ("public_key", "capabilities")):
            try:
                from secureagentnet.identify.trust_chain import TrustChainService
                TrustChainService.reissue(agent_id)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(f"Could not re-issue manifest for {agent_id}: {exc}")
        return cls._agents[agent_id]

    @classmethod
    def update_trust_score(cls, agent_id: str, delta: float) -> float:
        if agent_id not in cls._agents:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
        current = cls._agents[agent_id]["trust_score"]
        new_score = max(0.0, min(100.0, current + delta))
        cls._agents[agent_id]["trust_score"] = new_score
        cls._agents[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
        cls._persist()
        if new_score < 20:
            logger.warning(f"Agent {agent_id} trust score critically low: {new_score}")
        return new_score

    @classmethod
    def revoke_agent(cls, agent_id: str) -> bool:
        if agent_id not in cls._agents:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
        cls._agents[agent_id]["status"] = AgentStatus.REVOKED.value
        cls._persist()
        logger.warning(f"Agent {agent_id} revoked")
        return True

    @classmethod
    def deregister_agent(cls, agent_id: str) -> bool:
        """Permanently remove an agent (used to prune stale auto-discovered
        agents). Unlike revoke, this deletes the record from memory and the DB."""
        existed = agent_id in cls._agents
        cls._agents.pop(agent_id, None)
        cls._persist()
        try:
            from secureagentnet.database.repositories import AgentRepository
            AgentRepository.delete_one(str(agent_id))
        except Exception:
            pass
        try:
            from secureagentnet.identify.trust_chain import TrustChainService
            TrustChainService.delete(agent_id)
        except Exception:
            pass
        return existed

    @classmethod
    def suspend_agent(cls, agent_id: str) -> bool:
        if agent_id not in cls._agents:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
        cls._agents[agent_id]["status"] = AgentStatus.SUSPENDED.value
        cls._persist()
        logger.warning(f"Agent {agent_id} suspended")
        return True

    @classmethod
    def mark_rogue(cls, agent_id: str) -> bool:
        if agent_id not in cls._agents:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
        cls._agents[agent_id]["status"] = AgentStatus.ROGUE.value
        cls._agents[agent_id]["trust_score"] = 0.0
        cls._persist()
        logger.critical(f"Agent {agent_id} marked as ROGUE")
        return True

    @classmethod
    def get_active_count(cls) -> int:
        return len([a for a in cls._agents.values() if a["status"] == AgentStatus.ACTIVE.value])

    @classmethod
    def get_total_count(cls) -> int:
        return len(cls._agents)

    @classmethod
    def check_agent_active(cls, agent_id: str) -> bool:
        agent = cls.get_agent(agent_id)
        if not agent:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
        if agent["status"] == AgentStatus.SUSPENDED.value:
            raise AgentSuspendedError(f"Agent {agent_id} is suspended")
        if agent["status"] == AgentStatus.REVOKED.value:
            raise AgentSuspendedError(f"Agent {agent_id} is revoked")
        if agent["status"] == AgentStatus.ROGUE.value:
            raise AgentSuspendedError(f"Agent {agent_id} is marked as rogue")
        return agent["status"] == AgentStatus.ACTIVE.value

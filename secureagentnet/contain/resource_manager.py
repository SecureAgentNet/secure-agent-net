import logging
from typing import Dict, Optional
from secureagentnet.database.repositories import ContainerRepository

logger = logging.getLogger("SecureAgentNet.Contain.ResourceManager")


class ResourceQuota:
    def __init__(
        self,
        cpu_limit: float = 1.0,
        memory_limit_mb: int = 512,
        disk_read_bps: int = 10 * 1024 * 1024,
        disk_write_bps: int = 5 * 1024 * 1024,
        pids_limit: int = 50,
        cpu_quota: Optional[int] = None,
    ):
        self.cpu_limit = cpu_limit
        self.memory_limit_mb = memory_limit_mb
        self.disk_read_bps = disk_read_bps
        self.disk_write_bps = disk_write_bps
        self.pids_limit = pids_limit
        self.cpu_quota = cpu_quota or int(cpu_limit * 100000)

    def to_docker_kwargs(self) -> Dict:
        return {
            "cpu_period": 100000,
            "cpu_quota": self.cpu_quota,
            "mem_limit": f"{self.memory_limit_mb}m",
            "pids_limit": self.pids_limit,
            "blkio_weight": 500,
        }

    def to_dict(self) -> Dict:
        return {
            "cpu_limit": self.cpu_limit,
            "memory_limit_mb": self.memory_limit_mb,
            "disk_read_bps": self.disk_read_bps,
            "disk_write_bps": self.disk_write_bps,
            "pids_limit": self.pids_limit,
            "cpu_quota": self.cpu_quota,
        }


class ContainerResourceManager:
    _containers: Dict[str, Dict] = {}
    _loaded: bool = False

    @classmethod
    def _persist(cls):
        ContainerRepository.save_all(cls._containers)

    @classmethod
    def _load(cls):
        cls._containers = ContainerRepository.load_all()

    @classmethod
    def _ensure_loaded(cls):
        if not cls._loaded:
            cls._load()
            cls._loaded = True

    @classmethod
    def register_container(cls, container_id: str, agent_id: str, quota: ResourceQuota):
        cls._ensure_loaded()
        cls._containers[container_id] = {
            "container_id": container_id,
            "agent_id": agent_id,
            "quota": quota.to_dict(),
            "status": "creating",
        }
        cls._persist()
        logger.info(f"Container {container_id} registered for agent {agent_id}")

    @classmethod
    def update_status(cls, container_id: str, status: str):
        cls._ensure_loaded()
        if container_id in cls._containers:
            cls._containers[container_id]["status"] = status
            cls._persist()

    @classmethod
    def remove_container(cls, container_id: str):
        cls._ensure_loaded()
        cls._containers.pop(container_id, None)
        cls._persist()

    @classmethod
    def get_container(cls, container_id: str) -> Optional[Dict]:
        cls._ensure_loaded()
        return cls._containers.get(container_id)

    @classmethod
    def get_agent_containers(cls, agent_id: str) -> list:
        cls._ensure_loaded()
        return [c for c in cls._containers.values() if c["agent_id"] == agent_id]

    @classmethod
    def get_running_count(cls) -> int:
        cls._ensure_loaded()
        return len([c for c in cls._containers.values() if c.get("status") == "running"])

    @classmethod
    def get_total_count(cls) -> int:
        cls._ensure_loaded()
        return len(cls._containers)

    @classmethod
    def get_resource_usage_summary(cls) -> Dict:
        cls._ensure_loaded()
        total_memory = 0
        total_cpu = 0.0
        for container in cls._containers.values():
            quota = container.get("quota", {})
            total_memory += quota.get("memory_limit_mb", 0)
            total_cpu += quota.get("cpu_limit", 0)
        return {
            "total_containers": len(cls._containers),
            "total_memory_mb": total_memory,
            "total_cpu_cores": total_cpu,
        }


def get_default_quota() -> ResourceQuota:
    return ResourceQuota(
        cpu_limit=1.0,
        memory_limit_mb=512,
        pids_limit=50,
    )


def get_minimal_quota() -> ResourceQuota:
    return ResourceQuota(
        cpu_limit=0.5,
        memory_limit_mb=128,
        pids_limit=20,
    )


def get_heavy_quota() -> ResourceQuota:
    return ResourceQuota(
        cpu_limit=2.0,
        memory_limit_mb=2048,
        pids_limit=100,
    )

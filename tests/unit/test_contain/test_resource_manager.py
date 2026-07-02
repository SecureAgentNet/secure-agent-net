import pytest
from secureagentnet.contain.resource_manager import (
    ResourceQuota,
    ContainerResourceManager,
    get_default_quota,
    get_minimal_quota,
    get_heavy_quota,
)


class TestResourceQuota:
    def test_resource_quota_default(self):
        quota = get_default_quota()
        assert quota.cpu_limit == 1.0
        assert quota.memory_limit_mb == 512
        assert quota.pids_limit == 50

    def test_resource_quota_minimal(self):
        quota = get_minimal_quota()
        assert quota.cpu_limit == 0.5
        assert quota.memory_limit_mb == 128
        assert quota.pids_limit == 20

    def test_resource_quota_heavy(self):
        quota = get_heavy_quota()
        assert quota.cpu_limit == 2.0
        assert quota.memory_limit_mb == 2048
        assert quota.pids_limit == 100

    def test_resource_quota_custom(self):
        quota = ResourceQuota(cpu_limit=0.25, memory_limit_mb=64, pids_limit=10)
        assert quota.cpu_limit == 0.25
        assert quota.memory_limit_mb == 64
        assert quota.pids_limit == 10

    def test_resource_quota_cpu_quota_default(self):
        quota = ResourceQuota(cpu_limit=2.0)
        assert quota.cpu_quota == 200000

    def test_resource_quota_cpu_quota_custom(self):
        quota = ResourceQuota(cpu_limit=1.0, cpu_quota=50000)
        assert quota.cpu_quota == 50000

    def test_resource_quota_to_docker_kwargs(self):
        quota = ResourceQuota(cpu_limit=1.0, memory_limit_mb=256, pids_limit=30)
        kwargs = quota.to_docker_kwargs()
        assert kwargs["cpu_period"] == 100000
        assert kwargs["cpu_quota"] == 100000
        assert kwargs["mem_limit"] == "256m"
        assert kwargs["pids_limit"] == 30
        assert kwargs["blkio_weight"] == 500

    def test_resource_quota_to_dict(self):
        quota = ResourceQuota(cpu_limit=1.5, memory_limit_mb=1024)
        d = quota.to_dict()
        assert d["cpu_limit"] == 1.5
        assert d["memory_limit_mb"] == 1024
        assert d["pids_limit"] == 50
        assert d["cpu_quota"] == 150000


class TestContainerResourceManager:
    @pytest.fixture(autouse=True)
    def reset(self):
        ContainerResourceManager._containers = {}

    def test_container_resource_manager_register(self):
        quota = get_default_quota()
        ContainerResourceManager.register_container(
            container_id="container-1",
            agent_id="agent-1",
            quota=quota,
        )
        container = ContainerResourceManager.get_container("container-1")
        assert container is not None
        assert container["container_id"] == "container-1"
        assert container["agent_id"] == "agent-1"
        assert container["status"] == "creating"
        assert container["quota"]["memory_limit_mb"] == 512

    def test_container_resource_manager_count(self):
        q = get_default_quota()
        ContainerResourceManager.register_container("c1", "a1", q)
        ContainerResourceManager.register_container("c2", "a1", q)
        ContainerResourceManager.register_container("c3", "a2", q)
        assert ContainerResourceManager.get_total_count() == 3

    def test_container_resource_manager_get_running_count(self):
        q = get_default_quota()
        ContainerResourceManager.register_container("c1", "a1", q)
        ContainerResourceManager.update_status("c1", "running")
        ContainerResourceManager.register_container("c2", "a1", q)
        assert ContainerResourceManager.get_running_count() == 1

    def test_container_resource_manager_get_agent_containers(self):
        q = get_default_quota()
        ContainerResourceManager.register_container("c1", "a1", q)
        ContainerResourceManager.register_container("c2", "a1", q)
        ContainerResourceManager.register_container("c3", "a2", q)
        containers = ContainerResourceManager.get_agent_containers("a1")
        assert len(containers) == 2

    def test_container_resource_manager_remove_container(self):
        q = get_default_quota()
        ContainerResourceManager.register_container("c1", "a1", q)
        assert ContainerResourceManager.get_total_count() == 1
        ContainerResourceManager.remove_container("c1")
        assert ContainerResourceManager.get_total_count() == 0

    def test_container_resource_manager_get_resource_usage_summary(self):
        q1 = get_minimal_quota()
        q2 = get_default_quota()
        ContainerResourceManager.register_container("c1", "a1", q1)
        ContainerResourceManager.register_container("c2", "a2", q2)
        summary = ContainerResourceManager.get_resource_usage_summary()
        assert summary["total_containers"] == 2
        assert summary["total_memory_mb"] == 128 + 512
        assert summary["total_cpu_cores"] == 0.5 + 1.0

    def test_container_resource_manager_update_status_nonexistent(self):
        ContainerResourceManager.update_status("no-such-container", "running")

    def test_container_resource_manager_get_container_nonexistent(self):
        assert ContainerResourceManager.get_container("no-such-container") is None

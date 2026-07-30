import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from secureagentnet.core.pipeline import ITCDPipeline
from secureagentnet.track.models import AgentActionRequest
from secureagentnet.core.constants import AgentStatus
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.identify.capability_profiler import CapabilityProfiler


@pytest.fixture(autouse=True)
def reset_state():
    IdentityRegistry._agents = {}
    IdentityRegistry._initialized = False
    IdentityRegistry.initialize()
    CapabilityProfiler._mock_db = {
        "agent-007": ["read_file", "execute_sql", "search_web"],
        "agent-rogue": ["search_web"],
    }


@pytest.fixture
def pipeline():
    with (
        patch("secureagentnet.decide.model_providers.requests.post") as mock_ollama,
        patch("secureagentnet.contain.container_provisioner.docker.from_env") as mock_docker,
        patch("hvac.Client") as mock_vault,
    ):
        mock_ollama_response = MagicMock()
        mock_ollama_response.status_code = 200
        mock_ollama_response.json.return_value = {"response": "SCORE: 0.1\nREASON: Safe."}
        mock_ollama.return_value = mock_ollama_response

        mock_docker_client = MagicMock()
        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = b"output"
        mock_docker_client.containers.run.return_value = mock_container
        mock_docker_client.containers.create.return_value = mock_container
        mock_docker_client.containers.get.return_value = mock_container
        mock_docker.return_value = mock_docker_client

        mock_vault_client = MagicMock()
        mock_vault_client.secrets.kv.v2.create_or_update_secret.return_value = {"data": {"version": 1}}
        mock_vault.return_value = mock_vault_client

        yield ITCDPipeline()


@pytest.mark.asyncio
async def test_pipeline_blocks_rogue_agent(pipeline):
    agent = IdentityRegistry.register_agent({
        "name": "rogue-agent",
        "type": "Custom",
    })
    agent_id = agent["agent_id"]
    pipeline.rogue_detector._anomaly_threshold = 0.5
    pipeline.rogue_detector._failure_threshold = 1
    for _ in range(3):
        pipeline.rogue_detector.record_failure(agent_id)
        pipeline.rogue_detector.record_request(agent_id, "read_file")

    pipeline.rogue_detector._rate_limit = 1

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="/tmp/data.txt",
        intent_summary="Reading a file",
        payload={},
    )
    result = await pipeline.execute_agent_action(agent_id, request, "cat /tmp/data.txt")
    assert result["status"] == "blocked"
    assert "rogue" in result["reason"].lower() or "suspicious" in result["reason"].lower()
    assert result["phase"] == "IDENTIFY"


@pytest.mark.asyncio
async def test_pipeline_blocks_kill_switch_active(pipeline):
    agent = IdentityRegistry.register_agent({
        "name": "normal-agent",
        "capabilities": {"read": True},
    })
    agent_id = agent["agent_id"]
    pipeline.kill_switch._activate()

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="/tmp/test.txt",
        intent_summary="Reading test file",
        payload={},
    )
    result = await pipeline.execute_agent_action(agent_id, request, "cat /tmp/test.txt")
    assert result["status"] == "blocked"
    assert "Kill-switch" in result["reason"]
    assert result["phase"] == "IDENTIFY"


@pytest.mark.asyncio
async def test_pipeline_blocks_circuit_breaker_open(pipeline):
    agent = IdentityRegistry.register_agent({
        "name": "circuit-agent",
    })
    agent_id = agent["agent_id"]
    pipeline.circuit_breaker.failure_threshold = 1
    pipeline.circuit_breaker.record_failure(agent_id)

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="/tmp/test.txt",
        intent_summary="Reading test file",
        payload={},
    )
    result = await pipeline.execute_agent_action(agent_id, request, "cat /tmp/test.txt")
    assert result["status"] == "blocked"
    assert "Circuit Breaker" in result["reason"]


@pytest.mark.asyncio
async def test_pipeline_blocks_unauthorized_action(pipeline):
    agent = IdentityRegistry.register_agent({
        "name": "limited-agent",
        "capabilities": {"read_file": True},
    })
    agent_id = agent["agent_id"]

    request = AgentActionRequest(
        action_name="delete_database",
        target_resource="production_db",
        intent_summary="Deleting production data",
        payload={},
    )
    result = await pipeline.execute_agent_action(agent_id, request, "rm -rf /data")
    assert result["status"] == "blocked"
    assert "capability" in result["reason"].lower()
    assert result["phase"] == "IDENTIFY"


@pytest.mark.asyncio
async def test_pipeline_passes_authorized_action(pipeline):
    agent = IdentityRegistry.register_agent({
        "name": "good-agent",
        "capabilities": {"read_file": True},
    })
    agent_id = agent["agent_id"]

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="/tmp/test.txt",
        intent_summary="Reading test file",
        payload={},
    )
    result = await pipeline.execute_agent_action(agent_id, request, "cat /tmp/test.txt")
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_pipeline_blocks_inactive_agent(pipeline):
    agent = IdentityRegistry.register_agent({
        "name": "inactive-agent",
    })
    agent_id = agent["agent_id"]
    IdentityRegistry.suspend_agent(agent_id)

    request = AgentActionRequest(
        action_name="read_file",
        target_resource="/tmp/test.txt",
        intent_summary="Reading test file",
        payload={},
    )
    result = await pipeline.execute_agent_action(agent_id, request, "cat /tmp/test.txt")
    assert result["status"] == "blocked"
    assert "suspended" in result["reason"].lower()


@pytest.mark.asyncio
async def test_get_pipeline_status(pipeline):
    IdentityRegistry.register_agent({"name": "agent-a"})
    IdentityRegistry.register_agent({"name": "agent-b"})
    status = pipeline.get_pipeline_status()
    assert "kill_switch" in status
    assert "circuit_breaker" in status
    assert "rogue_detector" in status
    assert "containers" in status
    assert "agents" in status
    assert status["agents"]["active"] == 2
    assert status["agents"]["total"] == 2

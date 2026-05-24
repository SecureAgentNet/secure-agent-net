import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone

from src.core.config import Settings, get_settings
from src.identify.identity_registry import IdentityRegistry
from src.core.constants import AgentStatus
from src.track.models import AgentActionRequest
from src.core.pipeline import ITCDPipeline
from src.decide import DecisionGateway
from src.contain.container_provisioner import ContainerProvisioner
from src.decide.circuit_breaker import CircuitBreaker
from src.decide.kill_switch import KillSwitchController
from src.identify.rogue_detector import RogueDetector
from src.track.structured_logger import AgentAuditor, StructuredLogger
from src.decide.semantic_evaluator import SemanticEvaluator


@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    monkeypatch.setenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
    monkeypatch.setenv("OLLAMA_MODEL", "llama2:test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-testing")
    monkeypatch.setenv("AGENT_JWT_ALGORITHM", "HS256")
    from src.database.connection import dispose_engine
    dispose_engine()
    get_settings.cache_clear()
    settings = get_settings()
    return settings


@pytest.fixture(autouse=True)
def reset_identity_registry():
    from src.database.repositories import AgentRepository
    from src.database.connection import dispose_engine
    from src.utils.persistence import PersistenceStore
    PersistenceStore.delete("identity_registry")
    dispose_engine()
    AgentRepository.save_all({})
    IdentityRegistry._agents = {}
    IdentityRegistry._initialized = False
    IdentityRegistry.initialize()


@pytest.fixture(autouse=True)
def reset_log_indexer():
    from src.track.log_indexer import LogIndexer
    from src.database import models
    from src.database.connection import get_db_session, dispose_engine
    from sqlalchemy import delete as sa_delete
    from src.utils.persistence import PersistenceStore
    PersistenceStore.delete("log_indexer")
    dispose_engine()
    try:
        with get_db_session() as session:
            session.execute(sa_delete(models.AuditLogEntry))
    except Exception:
        pass
    LogIndexer._events = []
    LogIndexer.initialize()


@pytest.fixture(autouse=True)
def reset_capability_profiler():
    from src.identify.capability_profiler import CapabilityProfiler
    from src.utils.persistence import PersistenceStore
    PersistenceStore.delete("capability_profiler")
    CapabilityProfiler._mock_db = {
        "agent-007": ["read_file", "execute_sql", "search_web"],
        "agent-rogue": ["search_web"],
    }
    CapabilityProfiler._loaded = False


@pytest.fixture(autouse=True)
def reset_persistence():
    from src.utils.persistence import PersistenceStore
    from src.database.repositories import (
        CircuitBreakerRepository, KillSwitchRepository, ContainerRepository
    )
    for key in ("rogue_detector",):
        PersistenceStore.delete(key)
    CircuitBreakerRepository.save_all({})
    KillSwitchRepository.save({})
    ContainerRepository.save_all({})


@pytest.fixture
def mock_vault_client(monkeypatch):
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.create_or_update_secret.return_value = {
        "data": {"version": 1}
    }
    monkeypatch.setattr("hvac.Client", lambda url=None, token=None: mock_client)
    return mock_client


@pytest.fixture
def mock_docker_client(monkeypatch):
    from docker.errors import APIError
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.return_value = b"stdout output"
    mock_client.containers.run.return_value = mock_container
    mock_client.images.get.return_value = MagicMock()
    monkeypatch.setattr("docker.from_env", lambda: mock_client)
    monkeypatch.setattr("src.contain.container_provisioner.docker.from_env", lambda: mock_client)
    return mock_client


@pytest.fixture
def mock_ollama(monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "SCORE: 0.1\nREASON: Safe request."}
    monkeypatch.setattr("requests.post", lambda url, json, timeout: mock_response)
    return mock_response


@pytest.fixture
def sample_agent():
    agent_data = {
        "name": "test-agent-alpha",
        "type": "Custom",
        "description": "A test agent for unit tests",
        "public_key": "test-public-key-12345",
        "capabilities": {"read": True, "write": False},
        "metadata": {"owner": "test-team"},
        "created_by": "test-user",
    }
    agent = IdentityRegistry.register_agent(agent_data)
    return agent


@pytest.fixture
def sample_action_request():
    return AgentActionRequest(
        action_name="read_file",
        target_resource="/tmp/test.txt",
        intent_summary="Reading a test file for verification",
        payload={"file_path": "/tmp/test.txt", "encoding": "utf-8"},
    )


@pytest.fixture
def pipeline(mock_settings, mock_vault_client, mock_docker_client, mock_ollama):
    pipe = ITCDPipeline()
    return pipe

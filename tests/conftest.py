import pytest
import os
import tempfile
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone
from pathlib import Path

from secureagentnet.core.config import Settings, get_settings
from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.core.constants import AgentStatus
from secureagentnet.track.models import AgentActionRequest
from secureagentnet.core.pipeline import ITCDPipeline
from secureagentnet.decide import DecisionGateway
from secureagentnet.contain.container_provisioner import ContainerProvisioner
from secureagentnet.decide.circuit_breaker import CircuitBreaker
from secureagentnet.decide.kill_switch import KillSwitchController
from secureagentnet.identify.rogue_detector import RogueDetector
from secureagentnet.track.structured_logger import AgentAuditor, StructuredLogger
from secureagentnet.decide.semantic_evaluator import SemanticEvaluator


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path, monkeypatch):
    data_dir = tmp_path / ".secureagentnet" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    tldextract_cache = tmp_path / ".tldextract_cache"
    tldextract_cache.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("INSTALL_DIR", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
    monkeypatch.setenv("TLDEXTRACT_CACHE", str(tldextract_cache))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SAN_TESTING", "1")
    yield


@pytest.fixture(autouse=True)
def mock_redis(monkeypatch):
    monkeypatch.setattr("secureagentnet.utils.redis_client.is_available", lambda: False)
    monkeypatch.setattr("secureagentnet.utils.redis_client.get_limiter_storage_uri", lambda: "memory://")
    monkeypatch.setattr("secureagentnet.identify.authentication.is_available", lambda: False)


@pytest.fixture(autouse=True)
def disable_limiter():
    try:
        from secureagentnet.interfaces.web_dashboard.app import limiter
        limiter.enabled = False
    except ImportError:
        pass


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
    from secureagentnet.database.connection import dispose_engine
    dispose_engine()
    get_settings.cache_clear()
    settings = get_settings()
    return settings


@pytest.fixture(autouse=True)
def reset_identity_registry():
    from secureagentnet.database.repositories import AgentRepository
    from secureagentnet.database.connection import dispose_engine, init_database
    from secureagentnet.utils.persistence import PersistenceStore
    PersistenceStore.delete("identity_registry")
    dispose_engine()
    init_database()
    AgentRepository.save_all({})
    IdentityRegistry._agents = {}
    IdentityRegistry._initialized = False
    IdentityRegistry.initialize()


@pytest.fixture(autouse=True)
def reset_log_indexer():
    from secureagentnet.track.log_indexer import LogIndexer
    from secureagentnet.database import models
    from secureagentnet.database.connection import get_db_session, dispose_engine, init_database
    from sqlalchemy import delete as sa_delete
    from secureagentnet.utils.persistence import PersistenceStore
    PersistenceStore.delete("log_indexer")
    dispose_engine()
    init_database()
    try:
        with get_db_session() as session:
            session.execute(sa_delete(models.AuditLogEntry))
    except Exception:
        pass
    LogIndexer._events = []
    LogIndexer.initialize()


@pytest.fixture(autouse=True)
def reset_capability_profiler():
    from secureagentnet.identify.capability_profiler import CapabilityProfiler, _SEED_CAPABILITIES
    _SEED_CAPABILITIES.clear()
    _SEED_CAPABILITIES.update({
        "agent-007": ["read_file", "execute_sql", "search_web"],
        "agent-rogue": ["search_web"],
    })


@pytest.fixture(autouse=True)
def reset_persistence():
    from secureagentnet.utils.persistence import PersistenceStore
    from secureagentnet.database.repositories import (
        CircuitBreakerRepository, KillSwitchRepository, ContainerRepository
    )
    for key in ("rogue_detector", "kill_switch"):
        PersistenceStore.delete(key)
    CircuitBreakerRepository.save_all({})
    KillSwitchRepository.save({
        "_armed": True,
        "_active": False,
        "_trigger_count": 0,
        "_denial_counts": {},
        "_last_triggered_at": None,
        "_last_reset_at": None,
    })
    ContainerRepository.save_all({})

    # Reset in-memory state of any cached global pipelines
    import sys
    for module_name in ("secureagentnet.interfaces.web_dashboard.app", "secureagentnet.interfaces.cli.commands"):
        if module_name in sys.modules:
            try:
                mod = sys.modules[module_name]
                pipeline = getattr(mod, "pipeline", None)
                if pipeline and hasattr(pipeline, "kill_switch"):
                    pipeline.kill_switch._active = False
                    pipeline.kill_switch._trigger_count = 0
                    pipeline.kill_switch._denial_counts.clear()
                    pipeline.kill_switch._armed = True
            except Exception:
                pass




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
    monkeypatch.setattr("secureagentnet.contain.container_provisioner.docker.from_env", lambda: mock_client)
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

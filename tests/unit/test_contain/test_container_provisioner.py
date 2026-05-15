import pytest
from unittest.mock import MagicMock, patch
from src.contain.models import ExecutionRequest, SandboxConfig
from src.contain.container_provisioner import ContainerProvisioner


@pytest.fixture
def mock_docker_client(monkeypatch):
    """Mocks the docker environment so tests don't actually spin up containers."""
    mock_client = MagicMock()

    # Mock container instance
    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.side_effect = [
        b"Hello from sandbox\n", # stdout
        b""                      # stderr
    ]

    # Mock containers.run to return our mock container
    mock_client.containers.run.return_value = mock_container
    mock_client.containers.get.return_value = mock_container

    # Patch docker.from_env
    monkeypatch.setattr("src.contain.container_provisioner.docker.from_env", lambda: mock_client)

    return mock_client, mock_container


def test_run_in_sandbox_success(mock_docker_client):
    mock_client, mock_container = mock_docker_client

    provisioner = ContainerProvisioner()
    request = ExecutionRequest(
        command="echo 'Hello from sandbox'"
    )

    # Execute
    result = provisioner.run_in_sandbox(request)

    # Assertions
    assert result.exit_code == 0
    assert result.stdout == "Hello from sandbox\n"
    assert result.stderr == ""
    assert result.was_killed is False
    assert result.execution_time_ms >= 0

    # Verify the container was run with the strict security defaults
    run_kwargs = mock_client.containers.run.call_args[1]
    assert run_kwargs["image"] == "python:3.11-slim"
    assert run_kwargs["mem_limit"] == "128m"
    assert run_kwargs["network_disabled"] is True
    assert run_kwargs["read_only"] is True
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert any("seccomp" in opt for opt in run_kwargs["security_opt"])

    # Verify the container was forcefully removed
    mock_container.remove.assert_called_with(force=True)


def test_run_in_sandbox_timeout(mock_docker_client):
    mock_client, mock_container = mock_docker_client

    # Make the wait function raise a timeout exception (mocking requests.exceptions.ReadTimeout)
    class ReadTimeout(Exception): pass
    mock_container.wait.side_effect = ReadTimeout("Timed out")

    provisioner = ContainerProvisioner()
    request = ExecutionRequest(
        command="sleep 100"
    )

    result = provisioner.run_in_sandbox(request)

    # Assertions
    assert result.exit_code == 124 # Custom timeout code
    assert result.was_killed is True

    # Verify it was explicitly killed
    mock_container.kill.assert_called_once()
    # Verify it was still removed
    mock_container.remove.assert_called_with(force=True)

import pytest
from unittest.mock import MagicMock, patch
from secureagentnet.contain.models import ExecutionRequest, SandboxConfig
from secureagentnet.contain.container_provisioner import ContainerProvisioner


@pytest.fixture(autouse=True)
def mock_resource_manager(monkeypatch):
    monkeypatch.setattr(
        "secureagentnet.contain.container_provisioner.ContainerResourceManager.register_container",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "secureagentnet.contain.container_provisioner.ContainerResourceManager.update_status",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "secureagentnet.contain.container_provisioner.ContainerResourceManager.remove_container",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "secureagentnet.contain.container_provisioner.ContainerResourceManager.get_running_count",
        lambda: 0,
    )
    monkeypatch.setattr(
        "secureagentnet.contain.container_provisioner.ContainerResourceManager.get_agent_containers",
        lambda aid: [],
    )


@pytest.fixture
def mock_docker_client(monkeypatch):
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.side_effect = [b"Hello from sandbox\n", b""]

    mock_client.containers.run.return_value = mock_container
    mock_client.containers.create.return_value = mock_container
    mock_client.containers.get.return_value = mock_container
    mock_client.api.inspect_container.return_value = {
        "State": {"OOMKilled": False}
    }
    mock_container.stats.return_value = {
        "cpu_stats": {"cpu_usage": {"total_usage": 100000}, "system_cpu_usage": 1000000},
        "memory_stats": {"usage": 1024, "limit": 128 * 1024 * 1024},
        "networks": {"eth0": {"rx_bytes": 500, "tx_bytes": 200}},
    }

    monkeypatch.setattr("secureagentnet.contain.container_provisioner.docker.from_env", lambda: mock_client)
    monkeypatch.setattr("secureagentnet.contain.container_provisioner.create_isolated_network", lambda name="securenet_isolated": "securenet_isolated")
    return mock_client, mock_container


def test_run_in_sandbox_success(mock_docker_client):
    mock_client, mock_container = mock_docker_client
    provisioner = ContainerProvisioner()
    request = ExecutionRequest(command="echo 'Hello from sandbox'")
    result = provisioner.run_in_sandbox(request)

    assert result.exit_code == 0
    assert result.stdout == "Hello from sandbox\n"
    assert result.stderr == ""
    assert result.was_killed is False
    assert result.oom_killed is False
    assert result.execution_time_ms >= 0
    assert result.resource_usage.get("cpu_usage_percent") is not None

    run_kwargs = mock_client.containers.create.call_args[1]
    assert run_kwargs["image"] == "python:3.11-slim"
    assert run_kwargs["mem_limit"] == "128m"
    assert run_kwargs["network"] == "none"
    assert run_kwargs["read_only"] is True
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert any("seccomp" in opt for opt in run_kwargs["security_opt"])
    mock_container.start.assert_called_once()
    mock_container.remove.assert_called_with(force=True)


def test_run_in_sandbox_timeout(mock_docker_client):
    mock_client, mock_container = mock_docker_client
    class ReadTimeout(Exception):
        pass
    mock_container.wait.side_effect = ReadTimeout("Timed out")

    provisioner = ContainerProvisioner()
    request = ExecutionRequest(command="sleep 100")
    result = provisioner.run_in_sandbox(request)

    assert result.exit_code == 124
    assert result.was_killed is True
    mock_container.kill.assert_called_once()
    mock_container.remove.assert_called_with(force=True)


def test_run_in_sandbox_with_files(mock_docker_client):
    mock_client, mock_container = mock_docker_client
    import base64
    from secureagentnet.contain.models import InjectedFile

    provisioner = ContainerProvisioner()
    request = ExecutionRequest(
        command="python script.py",
        files=[InjectedFile(
            path="/workspace/script.py",
            content_base64=base64.b64encode(b"print('hello')").decode(),
            executable=True,
        )],
    )
    result = provisioner.run_in_sandbox(request)
    assert result.exit_code == 0


def test_run_in_sandbox_with_args_exec_form(mock_docker_client):
    mock_client, mock_container = mock_docker_client
    provisioner = ContainerProvisioner()
    request = ExecutionRequest(
        command="python -c 'print(1)'",
        args=["python", "-c", "print(1)"],
    )
    result = provisioner.run_in_sandbox(request)
    assert result.exit_code == 0
    run_kwargs = mock_client.containers.create.call_args[1]
    assert run_kwargs["command"] == ["python", "-c", "print(1)"]


def test_run_in_sandbox_custom_timeout(mock_docker_client):
    mock_client, mock_container = mock_docker_client
    provisioner = ContainerProvisioner()
    config = SandboxConfig(timeout_seconds=5)
    request = ExecutionRequest(command="sleep 1")
    result = provisioner.run_in_sandbox(request, config=config)
    assert result.exit_code == 0
    mock_container.wait.assert_called_with(timeout=5)


def test_run_in_sandbox_oom_detection(mock_docker_client):
    mock_client, mock_container = mock_docker_client
    mock_client.api.inspect_container.return_value = {
        "State": {"OOMKilled": True}
    }
    provisioner = ContainerProvisioner()
    request = ExecutionRequest(command="allocate_all")
    result = provisioner.run_in_sandbox(request)
    assert result.oom_killed is True
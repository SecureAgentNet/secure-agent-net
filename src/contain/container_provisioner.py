import docker
from docker.errors import ContainerError, ImageNotFound, APIError
import time
import logging
import json
import os
from typing import Optional, Tuple
from pathlib import Path
import uuid

from src.contain.models import SandboxConfig, ExecutionRequest, ExecutionResult

logger = logging.getLogger("SecureAgentNet.Contain")

class ContainerProvisioner:
    """
    Manages the lifecycle of ephemeral, highly-restricted Docker containers
    used to sandbox agent execution.
    """
    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to connect to Docker daemon: {e}")
            self.client = None

        # Load the default seccomp profile
        self.seccomp_profile = self._load_seccomp_profile()

    def _load_seccomp_profile(self) -> Optional[str]:
        """Loads the strict seccomp profile from the config directory."""
        profile_path = Path(__file__).parent.parent.parent / "config" / "seccomp_profile.json"
        try:
            with open(profile_path, 'r') as f:
                return json.dumps(json.load(f))
        except FileNotFoundError:
            logger.warning(f"Seccomp profile not found at {profile_path}. Using Docker default.")
            return None

    def run_in_sandbox(self, request: ExecutionRequest, config: Optional[SandboxConfig] = None) -> ExecutionResult:
        """
        Executes a command inside an isolated Docker sandbox.
        """
        if not self.client:
            raise RuntimeError("Docker client is not initialized. Cannot provision sandbox.")

        if config is None:
            config = SandboxConfig()

        sandbox_id = f"sandbox-{uuid.uuid4().hex[:8]}"
        start_time = time.time()
        was_killed = False

        # Ensure image exists
        try:
            self.client.images.get(config.image)
        except ImageNotFound:
            logger.info(f"Pulling image {config.image}...")
            self.client.images.pull(config.image)

        # Build HostConfig parameters for security
        security_opt = []
        if self.seccomp_profile:
            security_opt.append(f"seccomp={self.seccomp_profile}")

        # AppArmor is often enabled by default in Docker if the host supports it.
        # For stricter control, we explicitly set it if a custom profile exists.
        # security_opt.append("apparmor=secure-agent-profile")

        try:
            logger.info(f"Starting sandbox {sandbox_id} with command: {request.command}")

            # Spin up the ephemeral container
            container = self.client.containers.run(
                image=config.image,
                command=request.command,
                name=sandbox_id,
                detach=True,                 # Run in background so we can implement timeouts
                mem_limit=config.mem_limit,  # cgroup: memory
                cpu_quota=config.cpu_quota,  # cgroup: cpu
                network_disabled=config.network_disabled, # Network namespace
                read_only=config.read_only,  # Filesystem security
                cap_drop=config.drop_capabilities, # Kernel capabilities
                security_opt=security_opt,   # Seccomp & AppArmor
                working_dir=config.work_dir,
                environment=request.environment_vars,
                # In production, we would use tmpfs for a writable scratch space
                # tmpfs={config.work_dir: ''},
            )

            # Wait for execution to finish (with a timeout mechanism)
            # In a real async framework, you'd use asyncio sleep loops here.
            # We use a simple blocking wait with a short timeout for the demo.
            timeout_seconds = 10

            try:
                result = container.wait(timeout=timeout_seconds)
                exit_code = result.get('StatusCode', -1)
            except Exception as e: # Catching requests.exceptions.ReadTimeout
                logger.warning(f"Sandbox {sandbox_id} timed out. Killing container.")
                container.kill()
                was_killed = True
                exit_code = 124 # Common timeout exit code

            # Grab logs
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8')

        except APIError as e:
            logger.error(f"Docker API Error during sandbox execution: {e}")
            exit_code = -1
            stdout = ""
            stderr = str(e)
            was_killed = True
        finally:
            # Clean up the container aggressively
            try:
                # We need to get the container again in case it was created but failed
                c = self.client.containers.get(sandbox_id)
                c.remove(force=True)
                logger.info(f"Destroyed sandbox {sandbox_id}")
            except Exception:
                pass # Already removed or never created

        execution_time = int((time.time() - start_time) * 1000)

        return ExecutionResult(
            sandbox_id=sandbox_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            execution_time_ms=execution_time,
            was_killed=was_killed
        )

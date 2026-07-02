import logging
import os
import shutil
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DOCKER_SOCK = "/var/run/docker.sock"
RUNSC_BINARY = "runsc"
RUNSC_CONFIG_DIR = Path.home() / ".secureagentnet" / "gvisor"
RUNSC_CONFIG_FILE = RUNSC_CONFIG_DIR / "runsc.toml"


class MicroVMSandbox:
    """Enterprise-grade sandboxing using gVisor (runsc) or Firecracker.

    gVisor provides a user-space kernel that intercepts all syscalls,
    preventing container escape via host kernel vulnerabilities.
    Firecracker uses KVM-based micro-VM isolation.

    Usage:
        sandbox = MicroVMSandbox()
        if sandbox.is_available():
            runtime = sandbox.get_runtime()  # 'runsc' or 'runc'
    """

    RUNTIME_RUNC = "runc"
    RUNTIME_RUNSC = "runsc"

    def __init__(self, preferred_runtime: str = "auto"):
        self._preferred = preferred_runtime
        self._available_runtime: Optional[str] = None
        self._detect()

    def _detect(self):
        if self._preferred == self.RUNTIME_RUNSC:
            if self._runsc_available():
                self._available_runtime = self.RUNTIME_RUNSC
                logger.info("gVisor (runsc) detected — using micro-VM sandboxing")
            else:
                logger.warning("gVisor requested but not available — falling back to runc")
                self._available_runtime = self.RUNTIME_RUNC
        elif self._preferred == self.RUNTIME_RUNC:
            self._available_runtime = self.RUNTIME_RUNC
        else:
            if self._runsc_available():
                self._available_runtime = self.RUNTIME_RUNSC
            else:
                self._available_runtime = self.RUNTIME_RUNC

    def is_available(self) -> bool:
        return self._runsc_available()

    def get_runtime(self) -> str:
        return self._available_runtime or self.RUNTIME_RUNC

    def get_docker_runtime_flag(self) -> Optional[str]:
        """Return the Docker --runtime flag value, or None for default."""
        if self._available_runtime == self.RUNTIME_RUNSC:
            return self.RUNTIME_RUNSC
        return None

    def _runsc_available(self) -> bool:
        if shutil.which(RUNSC_BINARY):
            return True
        if os.path.exists(f"/usr/local/bin/{RUNSC_BINARY}"):
            return True
        if os.path.exists(f"/usr/bin/{RUNSC_BINARY}"):
            return True
        return False

    @classmethod
    def write_default_config(cls) -> Optional[str]:
        config = """# gVisor runsc configuration for SecureAgentNet
# Docs: https://gvisor.dev/docs/user_guide/configuration/

# Platform: systrap (default, fastest)
# Use kvm for hardware-assisted virtualization (requires KVM)
platform = "systrap"

# Network: host (use host network stack for speed) or sandbox (isolated network)
network = "sandbox"

# Filesystem overlay
overlay2 = "all"

# Enable strace for debugging
# strace = true

# Block dangerous syscalls even if seccomp misses them
directfs = false
"""
        RUNSC_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            RUNSC_CONFIG_FILE.write_text(config)
            logger.info("gVisor config written to %s", RUNSC_CONFIG_FILE)
            return str(RUNSC_CONFIG_FILE)
        except Exception as e:
            logger.error("Failed to write gVisor config: %s", e)
            return None

    @classmethod
    def docker_daemon_config_snippet(cls) -> str:
        """Return the Docker daemon.json snippet needed for gVisor runtime.

        Add this to /etc/docker/daemon.json and restart Docker:
          sudo systemctl restart docker
        """
        return """{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--platform=systrap",
        "--network=sandbox",
        "--overlay2=all"
      ]
    }
  }
}"""


def create_microvm_config(agent_id: str) -> dict:
    """Create Docker container kwargs for micro-VM sandboxing.

    Adds gVisor-specific security options beyond standard Docker.
    """
    sandbox = MicroVMSandbox()
    config = {}

    runtime = sandbox.get_docker_runtime_flag()
    if runtime:
        config["runtime"] = runtime
        config["labels"] = config.get("labels", {})
        config["labels"]["san.sandbox.runtime"] = "gvisor"

    return config

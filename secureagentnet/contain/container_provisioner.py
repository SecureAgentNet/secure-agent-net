import base64
import os
import subprocess
import sys
import tempfile
import time
import logging
import json
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path
import uuid

import docker
from docker.errors import ImageNotFound, APIError, DockerException

from secureagentnet.contain.models import SandboxConfig, ExecutionRequest, ExecutionResult, InjectedFile
from secureagentnet.contain.network_isolation import create_isolated_network, get_network_isolation_profile
from secureagentnet.contain.resource_manager import ContainerResourceManager, ResourceQuota
from secureagentnet.contain.security_profiles import APPARMOR_DEFAULT
from secureagentnet.contain.secret_injector import get_secret_injector
from secureagentnet.contain.network_whitelist import create_domain_whitelist_for_agent
from secureagentnet.contain.microvm import MicroVMSandbox, create_microvm_config
from secureagentnet.contain.dynamic_profiles import get_profile_compiler
from secureagentnet.utils.platform import docker_socket_path, detect_platform, Platform

logger = logging.getLogger("SecureAgentNet.Contain")

APPARMOR_PROFILE_NAME = "securenet-agent"


from dataclasses import dataclass, field


@dataclass
class SandboxHandle:
    """Handle to a provisioned-but-not-yet-executed sandbox.

    In ITCD order the container is created and fully isolated during the
    CONTAIN phase (before DECIDE). DECIDE then either approves execution
    (``execute_in_sandbox``) or denies it, in which case the container is
    destroyed without ever running the workload (``teardown_sandbox``).
    """
    sandbox_id: str
    container: object
    agent_id: str
    config: SandboxConfig
    secret_injector: object
    start_time: float = field(default_factory=time.time)
    started: bool = False


class ContainerProvisioner:
    def __init__(self):
        self.client = None
        plat = detect_platform()
        try:
            self.client = docker.from_env()
        except Exception as e:
            sock = docker_socket_path()
            if sock:
                try:
                    self.client = docker.DockerClient(base_url=f"unix://{sock}")
                    logger.info("Connected to Docker at %s", sock)
                except Exception:
                    pass
            if not self.client and plat in (Platform.MACOS, Platform.WINDOWS):
                logger.warning(
                    "Docker Desktop not detected (%s). Container sandboxing disabled.", plat.value
                )
            elif not self.client:
                logger.error("Failed to connect to Docker daemon: %s", e)

        self.seccomp_profile = self._load_seccomp_profile()
        self.apparmor_profile = self._load_apparmor_profile()

    def _load_seccomp_profile(self) -> Optional[str]:
        profile_path = Path(__file__).parent.parent.parent / "config" / "seccomp_profile.json"
        try:
            with open(profile_path, 'r') as f:
                profile_data = json.load(f)
            seccomp_json = json.dumps(profile_data)
            logger.info("Loaded seccomp profile (%d bytes)", len(seccomp_json))
            return seccomp_json
        except FileNotFoundError:
            logger.warning("Seccomp profile not found. Using Docker default.")
            return None
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load seccomp profile: %s. Using Docker default.", e)
            return None

    def _load_apparmor_profile(self) -> Optional[str]:
        if not self.client:
            return None
        platform = sys.platform
        if platform == "win32" or platform == "darwin":
            return None
        try:
            result = subprocess.run(
                ["which", "apparmor_parser"], capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        profiles_dir = Path.home() / ".secureagentnet" / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        profile_path = profiles_dir / "securenet-agent.aa"
        try:
            profile_path.write_text(APPARMOR_DEFAULT)
            logger.info(
                "AppArmor profile written to %s — load with: sudo apparmor_parser -r %s",
                profile_path, profile_path,
            )
            self._apparmor_profile_path = str(profile_path)
            return APPARMOR_PROFILE_NAME
        except Exception as e:
            logger.warning("Failed to write AppArmor profile: %s", e)
            return None

    def _check_container_limits(self, agent_id: str, config: SandboxConfig):
        total = ContainerResourceManager.get_running_count()
        if total >= config.max_concurrent_containers:
            raise RuntimeError(
                f"Global container limit reached ({total}/{config.max_concurrent_containers})"
            )
        agent_running = len(ContainerResourceManager.get_agent_containers(agent_id)) if agent_id else 0
        if agent_running >= config.max_containers_per_agent:
            raise RuntimeError(
                f"Agent container limit reached ({agent_running}/{config.max_containers_per_agent})"
            )

    @staticmethod
    def _workspace_volume_name(sandbox_id: str) -> str:
        return f"san-ws-{sandbox_id}"

    def _prepare_workspace_volume(self, volume_name: str, image: str, work_dir: str):
        """Make a fresh workspace volume writable by the unprivileged sandbox user.

        Docker creates a volume's mount point root-owned 0755. The sandbox runs
        as uid 1000, so without this the agent cannot write to its own working
        directory — while /tmp, which inherits 1777 from the image, can be
        written. A throwaway root container fixes the mode; it holds no agent
        code and exits immediately.

        Best-effort: a failure leaves the workspace readable but not writable,
        which is degraded rather than unsafe, so it must not fail provisioning.
        """
        try:
            self.client.containers.run(
                image, command=["chmod", "1777", work_dir],
                volumes={volume_name: {"bind": work_dir, "mode": "rw"}},
                user="0:0", network_mode="none", remove=True,
                labels={"managed_by": "secureagentnet", "purpose": "workspace-init"},
            )
        except Exception as e:
            logger.warning(
                "Could not make workspace volume %s writable (%s); the sandbox "
                "will see a read-only working directory", volume_name, e,
            )

    def _remove_workspace_volume(self, sandbox_id: str):
        """Drop a sandbox's workspace volume; a no-op when it never had one."""
        try:
            self.client.volumes.get(self._workspace_volume_name(sandbox_id)).remove(force=True)
            logger.debug("Removed workspace volume for %s", sandbox_id)
        except Exception:
            pass

    def _inject_files(self, sandbox_id: str, files: list[InjectedFile]):
        if not files:
            return
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"san_files_{sandbox_id}_"))
        try:
            for f in files:
                f.write_to(tmp_dir)
            container = self.client.containers.get(sandbox_id)
            for f in files:
                src = tmp_dir / f.path.lstrip("/")
                if src.exists():
                    with open(src, "rb") as fh:
                        container.put_archive(
                            str(Path(f.path).parent),
                            self._make_tar_archive(f.path, fh.read()),
                        )
            logger.info("Injected %d files into %s", len(files), sandbox_id)
        except Exception as e:
            # Swallowing this left the workload running against an empty
            # workspace and reporting "no matches" as though that were a result.
            logger.error("Failed to inject files into %s: %s", sandbox_id, e)
            raise RuntimeError(
                f"Could not inject {len(files)} file(s) into sandbox {sandbox_id}: {e}"
            ) from e
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _make_tar_archive(name: str, content: bytes) -> bytes:
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=Path(name).name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)
        return buf.read()

    def _collect_metrics(self, sandbox_id: str) -> dict:
        try:
            container = self.client.containers.get(sandbox_id)
            stats = container.stats(stream=False)
            cpu_stats = stats.get("cpu_stats", {})
            mem_stats = stats.get("memory_stats", {})
            net_stats = stats.get("networks", {})
            cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            system_delta = cpu_stats.get("system_cpu_usage", 1)
            cpu_percent = (cpu_delta / system_delta) * 100 if system_delta else 0
            mem_usage = mem_stats.get("usage", 0)
            mem_limit = mem_stats.get("limit", 0)
            total_rx = sum(n.get("rx_bytes", 0) for n in net_stats.values())
            total_tx = sum(n.get("tx_bytes", 0) for n in net_stats.values())
            return {
                "cpu_usage_percent": round(cpu_percent, 2),
                "memory_usage_bytes": mem_usage,
                "memory_limit_bytes": mem_limit,
                "network_rx_bytes": total_rx,
                "network_tx_bytes": total_tx,
            }
        except Exception as e:
            logger.debug("Failed to collect metrics for %s: %s", sandbox_id, e)
            return {}

    def _build_run_kwargs(
        self, request: ExecutionRequest, config: SandboxConfig,
        sandbox_id: str, agent_id: str,
    ) -> dict:
        """Assemble the fully-isolated Docker kwargs (seccomp, AppArmor, network,
        gVisor, tmpfs, resource limits, command). Shared by provisioning."""
        try:
            self.client.images.get(config.image)
        except ImageNotFound:
            logger.info("Pulling image %s...", config.image)
            self.client.images.pull(config.image)

        security_opt = []

        # --- Dynamic Seccomp Profile (per-agent capability synthesis) ---
        compiler = get_profile_compiler()
        dynamic_seccomp = compiler.get_seccomp_for_agent(agent_id)
        if dynamic_seccomp:
            security_opt.append(f"seccomp={dynamic_seccomp}")
            logger.info("Applied dynamic seccomp profile for agent %s", agent_id)
        elif self.seccomp_profile:
            security_opt.append(f"seccomp={self.seccomp_profile}")

        # --- Dynamic AppArmor Profile (least-privilege for agent caps) ---
        if self.apparmor_profile:
            dynamic_apparmor = compiler.get_apparmor_for_agent(agent_id)
            if dynamic_apparmor:
                try:
                    import subprocess as sp
                    result = sp.run(
                        ["sudo", "-n", "apparmor_parser", "-r", dynamic_apparmor],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode == 0:
                        security_opt.append(f"apparmor=securenet-agent-{str(hash(agent_id))[-8:]}")
                        logger.info("Loaded dynamic AppArmor profile for agent %s", agent_id)
                    else:
                        security_opt.append(f"apparmor={self.apparmor_profile}")
                        logger.warning("AppArmor parser failed for agent %s — using default profile", agent_id)
                except (OSError, sp.TimeoutExpired) as e:
                    security_opt.append(f"apparmor={self.apparmor_profile}")
                    logger.debug("Could not load dynamic AppArmor for agent %s: %s — using default", agent_id, e)
            else:
                security_opt.append(f"apparmor={self.apparmor_profile}")

        network_mode = None
        if config.network_disabled:
            network_mode = "none"
        else:
            get_network_isolation_profile(config.network_isolation_level)
            network_name = create_isolated_network()
            if network_name:
                network_mode = network_name

        # --- Network Whitelisting ---
        net_whitelist = create_domain_whitelist_for_agent(agent_id)

        run_kwargs = dict(
            image=config.image,
            name=sandbox_id,
            mem_limit=config.mem_limit,
            cpu_quota=config.cpu_quota,
            read_only=config.read_only,
            cap_drop=config.drop_capabilities,
            security_opt=security_opt,
            working_dir=config.work_dir,
            environment=request.environment_vars,
            user="1000:1000",
            pids_limit=50,
        )

        # --- gVisor Micro-VM Sandboxing ---
        microvm = create_microvm_config(agent_id)
        if microvm.get("runtime"):
            run_kwargs["runtime"] = microvm["runtime"]
            logger.info("Sandbox %s running with gVisor (runsc) micro-VM isolation", sandbox_id)
        if microvm.get("labels"):
            run_kwargs.setdefault("labels", {}).update(microvm["labels"])

        if network_mode:
            run_kwargs["network"] = network_mode

        whitelist_config = net_whitelist.to_docker_config()
        if whitelist_config.get("dns"):
            run_kwargs["dns"] = whitelist_config["dns"]
        if whitelist_config.get("dns_search"):
            run_kwargs["dns_search"] = whitelist_config["dns_search"]

        if config.read_only:
            size = config.tmpfs_size
            run_kwargs["tmpfs"] = {"/tmp": f"size={size},noexec,nosuid,nodev"}
            if request.files:
                # Injected files have to be written before the container starts,
                # and Docker refuses put_archive against a read-only rootfs — a
                # tmpfs at the workspace does not help, because the mount would
                # also shadow anything written underneath it. A dedicated volume
                # is writable for the injection and still leaves the rest of the
                # filesystem read-only.
                run_kwargs["volumes"] = {
                    self._workspace_volume_name(sandbox_id): {
                        "bind": config.work_dir, "mode": "rw",
                    }
                }
            else:
                # mode=1777 to match /tmp. The workspace is the container's
                # working directory but does not exist in the base image, so
                # Docker creates the mount point root-owned 0755 — leaving the
                # unprivileged sandbox user unable to write to its own working
                # directory. noexec/nosuid/nodev still apply, and the mount is
                # per-container and destroyed at teardown.
                run_kwargs["tmpfs"][config.work_dir] = (
                    f"size={size},noexec,nosuid,nodev,mode=1777"
                )

        if request.args:
            run_kwargs["command"] = request.args
        elif request.command and isinstance(request.command, list):
            run_kwargs["command"] = request.command
        else:
            run_kwargs["command"] = ["/bin/sh", "-c", str(request.command)]

        return run_kwargs

    def provision_sandbox(
        self, request: ExecutionRequest, config: Optional[SandboxConfig] = None,
    ) -> SandboxHandle:
        """CONTAIN phase: create the fully-isolated sandbox container *without*
        running the workload. The container exists with all security profiles,
        resource limits, network isolation, injected secrets and files applied,
        but its command has not yet executed — execution waits on DECIDE.
        """
        if not self.client:
            raise RuntimeError("Docker client is not initialized.")

        if config is None:
            config = SandboxConfig()

        sandbox_id = f"sandbox-{uuid.uuid4().hex[:8]}"
        agent_id = request.environment_vars.get("AGENT_ID", "")

        self._check_container_limits(agent_id, config)

        # --- Dynamic Secrets Injection ---
        secret_injector = get_secret_injector()
        injected_env = secret_injector.inject_into_environment(
            agent_id=agent_id,
            existing_env=request.environment_vars,
        )
        request.environment_vars = injected_env

        run_kwargs = self._build_run_kwargs(request, config, sandbox_id, agent_id)

        ContainerResourceManager.register_container(
            sandbox_id, agent_id,
            ResourceQuota(cpu_limit=1.0, memory_limit_mb=int(config.mem_limit.rstrip("m"))),
        )

        if request.files:
            # Per-sandbox and removed at teardown, so one agent's injected files
            # can never be visible to another's workspace.
            volume_name = self._workspace_volume_name(sandbox_id)
            self.client.volumes.create(
                name=volume_name,
                labels={"managed_by": "secureagentnet", "sandbox_id": sandbox_id},
            )

        try:
            container = self.client.containers.create(**run_kwargs)
        except (APIError, RuntimeError) as e:
            logger.error("Container provisioning error: %s", e)
            ContainerResourceManager.remove_container(sandbox_id)
            secret_injector.revoke_secrets(agent_id, sandbox_id)
            self._remove_workspace_volume(sandbox_id)
            raise

        ContainerResourceManager.update_status(sandbox_id, "provisioned")
        try:
            self._inject_files(sandbox_id, request.files)
            if request.files:
                # Must run after containers.create, which re-initialises the
                # volume's mount point and would undo an earlier chmod.
                self._prepare_workspace_volume(
                    self._workspace_volume_name(sandbox_id),
                    config.image, config.work_dir,
                )
        except Exception:
            container.remove(force=True)
            ContainerResourceManager.remove_container(sandbox_id)
            secret_injector.revoke_secrets(agent_id, sandbox_id)
            self._remove_workspace_volume(sandbox_id)
            raise
        logger.info(
            "Provisioned sandbox %s (image=%s) — contained, awaiting DECIDE",
            sandbox_id, config.image,
        )

        return SandboxHandle(
            sandbox_id=sandbox_id,
            container=container,
            agent_id=agent_id,
            config=config,
            secret_injector=secret_injector,
        )

    def execute_in_sandbox(self, handle: SandboxHandle) -> ExecutionResult:
        """DECIDE-approved execution: start the already-contained sandbox,
        run the workload to completion (or timeout) and collect results."""
        container = handle.container
        config = handle.config
        sandbox_id = handle.sandbox_id
        was_killed = False
        oom_killed = False
        metrics = {}

        try:
            logger.info(
                "Executing in sandbox %s (timeout=%ds)", sandbox_id, config.timeout_seconds
            )
            container.start()
            handle.started = True
            ContainerResourceManager.update_status(sandbox_id, "running")

            try:
                result = container.wait(timeout=config.timeout_seconds)
                exit_code = result.get("StatusCode", -1)
                state = self.client.api.inspect_container(sandbox_id)
                oom_killed = state.get("State", {}).get("OOMKilled", False)
            except Exception:
                logger.warning("Sandbox %s timed out — killing.", sandbox_id)
                container.kill()
                was_killed = True
                exit_code = 124

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            metrics = self._collect_metrics(sandbox_id)

        except APIError as e:
            logger.error("Docker API Error: %s", e)
            exit_code = -1
            stdout = ""
            stderr = str(e)
            was_killed = True
            ContainerResourceManager.update_status(sandbox_id, "failed")

        execution_time = int((time.time() - handle.start_time) * 1000)

        return ExecutionResult(
            sandbox_id=sandbox_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            execution_time_ms=execution_time,
            was_killed=was_killed,
            oom_killed=oom_killed,
            resource_usage=metrics,
        )

    def teardown_sandbox(self, handle: SandboxHandle, executed: bool = True):
        """Destroy a provisioned sandbox and revoke its secrets. Called after a
        successful run, or on DECIDE denial to kill the container un-executed."""
        sandbox_id = handle.sandbox_id
        try:
            c = self.client.containers.get(sandbox_id)
            c.remove(force=True)
            logger.info("Destroyed sandbox %s", sandbox_id)
        except Exception:
            pass
        finally:
            ContainerResourceManager.remove_container(sandbox_id)
            handle.secret_injector.revoke_secrets(handle.agent_id, sandbox_id)
            self._remove_workspace_volume(sandbox_id)

        if not executed:
            logger.info(
                "Sandbox %s torn down without execution (action denied by DECIDE)",
                sandbox_id,
            )

    def run_in_sandbox(
        self, request: ExecutionRequest, config: Optional[SandboxConfig] = None,
    ) -> ExecutionResult:
        """Convenience composition: provision → execute → teardown in one call.

        Retained for callers/tests that don't need the CONTAIN/DECIDE split. The
        ITCD pipeline drives the three phases separately so DECIDE runs between
        provisioning and execution.
        """
        handle = self.provision_sandbox(request, config)
        try:
            return self.execute_in_sandbox(handle)
        finally:
            self.teardown_sandbox(handle)

    def cleanup(self):
        self._unload_apparmor_profile()

    def _unload_apparmor_profile(self):
        path = getattr(self, "_apparmor_profile_path", None)
        if not path:
            return
        try:
            os.unlink(path)
            logger.info("AppArmor profile file removed.")
        except Exception as e:
            logger.debug("AppArmor cleanup skipped: %s", e)
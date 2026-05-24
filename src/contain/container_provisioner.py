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

from src.contain.models import SandboxConfig, ExecutionRequest, ExecutionResult, InjectedFile
from src.contain.network_isolation import create_isolated_network, get_network_isolation_profile
from src.contain.resource_manager import ContainerResourceManager, ResourceQuota
from src.contain.security_profiles import APPARMOR_DEFAULT
from src.utils.platform import docker_socket_path, detect_platform, Platform

logger = logging.getLogger("SecureAgentNet.Contain")

APPARMOR_PROFILE_NAME = "securenet-agent"


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
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", prefix="seccomp_", delete=False,
            )
            json.dump(profile_data, tmp)
            tmp.flush()
            tmp_path = tmp.name
            logger.info("Loaded seccomp profile to %s", tmp_path)
            return tmp_path
        except FileNotFoundError:
            logger.warning("Seccomp profile not found. Using Docker default.")
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
            logger.warning("Failed to inject files into %s: %s", sandbox_id, e)
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

    def run_in_sandbox(
        self, request: ExecutionRequest, config: Optional[SandboxConfig] = None,
    ) -> ExecutionResult:
        if not self.client:
            raise RuntimeError("Docker client is not initialized.")

        if config is None:
            config = SandboxConfig()

        sandbox_id = f"sandbox-{uuid.uuid4().hex[:8]}"
        start_time = time.time()
        was_killed = False
        oom_killed = False
        agent_id = request.environment_vars.get("AGENT_ID", "")

        self._check_container_limits(agent_id, config)

        try:
            self.client.images.get(config.image)
        except ImageNotFound:
            logger.info("Pulling image %s...", config.image)
            self.client.images.pull(config.image)

        ContainerResourceManager.register_container(
            sandbox_id, agent_id,
            ResourceQuota(cpu_limit=1.0, memory_limit_mb=int(config.mem_limit.rstrip("m"))),
        )

        security_opt = []
        if self.seccomp_profile:
            security_opt.append(f"seccomp={self.seccomp_profile}")
        if self.apparmor_profile:
            security_opt.append(f"apparmor={self.apparmor_profile}")

        network_mode = None
        network_name = None
        if config.network_disabled:
            network_mode = "none"
        else:
            iso_config = get_network_isolation_profile(config.network_isolation_level)
            network_name = create_isolated_network()
            if network_name:
                network_mode = network_name

        try:
            logger.info("Starting sandbox %s (image=%s, timeout=%ds)", sandbox_id, config.image, config.timeout_seconds)

            run_kwargs = dict(
                image=config.image,
                name=sandbox_id,
                detach=True,
                mem_limit=config.mem_limit,
                cpu_quota=config.cpu_quota,
                read_only=config.read_only,
                cap_drop=config.drop_capabilities,
                security_opt=security_opt,
                working_dir=config.work_dir,
                environment=request.environment_vars,
            )

            if network_mode:
                run_kwargs["network"] = network_mode

            if config.read_only:
                size = config.tmpfs_size
                run_kwargs["tmpfs"] = {
                    "/tmp": f"size={size},noexec,nosuid,nodev",
                    config.work_dir: f"size={size},noexec,nosuid,nodev",
                }

            if request.args:
                run_kwargs["command"] = request.args
            else:
                run_kwargs["command"] = request.command

            container = self.client.containers.run(**run_kwargs)
            ContainerResourceManager.update_status(sandbox_id, "running")

            self._inject_files(sandbox_id, request.files)

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

        except APIError as e:
            logger.error("Docker API Error: %s", e)
            exit_code = -1
            stdout = ""
            stderr = str(e)
            was_killed = True
            ContainerResourceManager.update_status(sandbox_id, "failed")
        except RuntimeError as e:
            logger.error("Container provisioning error: %s", e)
            raise
        finally:
            try:
                c = self.client.containers.get(sandbox_id)
                metrics = self._collect_metrics(sandbox_id)
                c.remove(force=True)
                ContainerResourceManager.remove_container(sandbox_id)
                logger.info("Destroyed sandbox %s", sandbox_id)
            except Exception:
                metrics = {}
                ContainerResourceManager.remove_container(sandbox_id)

        execution_time = int((time.time() - start_time) * 1000)

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

    def cleanup(self):
        self._unload_apparmor_profile()
        seccomp_path = getattr(self, "seccomp_profile", None)
        if seccomp_path and os.path.exists(seccomp_path):
            try:
                os.unlink(seccomp_path)
                logger.debug("Seccomp temp file removed.")
            except Exception:
                pass

    def _unload_apparmor_profile(self):
        path = getattr(self, "_apparmor_profile_path", None)
        if not path:
            return
        try:
            os.unlink(path)
            logger.info("AppArmor profile file removed.")
        except Exception as e:
            logger.debug("AppArmor cleanup skipped: %s", e)
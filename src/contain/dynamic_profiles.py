import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Capability → Syscall Mapping
# ---------------------------------------------------------------------------

CAPABILITY_SYSCALL_MAP = {
    "read_file": ["openat", "read", "close", "fstat", "getdents64", "lseek", "newfstatat"],
    "write_file": ["openat", "write", "close", "fsync", "rename", "mkdir"],
    "execute_code": ["execve", "execveat", "clone", "clone3", "fork", "vfork", "wait4", "rt_sigaction", "rt_sigprocmask", "arch_prctl"],
    "network_access": ["socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg"],
    "dns_resolve": ["connect", "sendto", "recvfrom", "socket"],
    "web_search": ["socket", "connect", "sendto", "recvfrom", "poll", "select", "epoll_create", "epoll_ctl", "epoll_wait"],
    "execute_sql": ["openat", "read", "write", "connect", "sendto", "recvfrom"],
    "container_management": [],  # no extra syscalls beyond essentials
    "admin": [],  # wildcard — all allowed
}

ESSENTIAL_SYSCALLS = [
    "read", "write", "openat", "close", "fstat", "lseek", "mmap", "mprotect",
    "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe2",
    "select", "sched_yield", "nanosleep", "clock_gettime", "getpid",
    "getuid", "geteuid", "getgid", "getegid", "exit", "exit_group",
    "futex", "set_robust_list", "rseq", "tgkill", "getrandom",
    "stat", "statfs", "statx", "fstatfs", "getcwd", "getdents64",
    "newfstatat", "prctl", "arch_prctl", "set_tid_address",
    "sched_getaffinity", "epoll_create", "epoll_ctl", "epoll_wait",
    "dup", "dup2", "fcntl", "chdir", "fchown", "fchmod", "faccessat",
    "readlink", "readlinkat", "capget", "capset", "setuid", "setgid",
    "setgroups", "setresuid", "setresgid", "prlimit64", "clone3",
    "rt_sigsuspend", "sigaltstack", "uname", "umask", "getppid", "getpgid",
]


APPARMOR_TEMPLATE = """#include <tunables/global>

profile securenet-agent-{agent_hash} flags=(attach_disconnected,mediate_deleted) {{
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Capability rules for agent: {agent_id}
  capability dac_override,
  capability dac_read_search,

  # Allowed filesystem access
  {fs_rules}

  # Network access
  {network_rules}

  # Execution
  {exec_rules}
}}
"""

FS_READ_RULE = "  {path}/ r,\n  {path}/** r,"
FS_WRITE_RULE = "  {path}/ rw,\n  {path}/** rw,"
NETWORK_DENY = "  deny network,\n"
NETWORK_ALLOW = "  network inet stream,\n  network inet dgram,"
EXEC_DENY = "  deny /usr/bin/** x,\n  deny /bin/** x,\n  deny /sbin/** x,"
EXEC_ALLOW = "  /usr/bin/python* rix,\n  /bin/sh rix,"


class DynamicProfileCompiler:
    """Compiles kernel-level AppArmor and seccomp profiles from agent capabilities.

    On container launch, reads the agent's capabilities from IdentityRegistry
    and generates tailored, least-privilege security profiles.
    """

    def __init__(self):
        self._apparmor_profile_path: Optional[str] = None
        self._compiled_profiles: Dict[str, str] = {}

    @classmethod
    def compile_seccomp_profile(
        cls,
        capabilities: Dict[str, object],
        platform_arch: str = "x86_64",
    ) -> str:
        """Generate a seccomp profile JSON allowing only syscalls the agent needs.

        Returns a JSON string suitable for Docker's seccomp={
            ...} security opt.
        """
        allowed_syscalls: Set[str] = set(ESSENTIAL_SYSCALLS)

        for cap, enabled in capabilities.items():
            if not enabled:
                continue
            cap_syscalls = CAPABILITY_SYSCALL_MAP.get(cap, [])
            allowed_syscalls.update(cap_syscalls)

        if capabilities.get("*") or capabilities.get("actions", {}).get("*"):
            return json.dumps({"defaultAction": "SCMP_ACT_ALLOW"})

        arch_map = {
            "x86_64": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"],
            "aarch64": ["SCMP_ARCH_AARCH64"],
        }

        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": arch_map.get(platform_arch, ["SCMP_ARCH_X86_64"]),
            "syscalls": [
                {
                    "names": sorted(allowed_syscalls),
                    "action": "SCMP_ACT_ALLOW",
                }
            ],
        }
        return json.dumps(profile)

    @classmethod
    def compile_apparmor_profile(
        cls,
        agent_id: str,
        capabilities: Dict[str, object],
    ) -> str:
        """Generate an AppArmor profile string for the given agent capabilities."""
        agent_hash = str(hash(agent_id))[-8:]

        has_network = any(
            capabilities.get(cap)
            for cap in ("network_access", "web_search", "dns_resolve", "execute_sql")
        ) or capabilities.get("*")

        has_exec = capabilities.get("execute_code") or capabilities.get("*")

        fs_rules = []
        base_paths = ["/tmp", "/workspace", "/usr/lib", "/usr/local/lib", "/lib", "/lib64"]
        for path in base_paths:
            fs_rules.append(FS_READ_RULE.format(path=path))
        if capabilities.get("write_file"):
            for path in ["/tmp", "/workspace"]:
                fs_rules.append(FS_WRITE_RULE.format(path=path))

        network_rules = NETWORK_ALLOW if has_network else NETWORK_DENY
        exec_rules = EXEC_ALLOW if has_exec else EXEC_DENY

        profile_str = APPARMOR_TEMPLATE.format(
            agent_hash=agent_hash,
            agent_id=agent_id,
            fs_rules="\n".join(fs_rules),
            network_rules=network_rules,
            exec_rules=exec_rules,
        )
        return profile_str

    def write_apparmor_profile(
        self,
        agent_id: str,
        capabilities: Dict[str, object],
    ) -> Optional[str]:
        """Write a compiled AppArmor profile to a temp file.

        Returns the path to the profile file, or None on failure.
        Does NOT load the profile into the kernel (requires root).
        """
        try:
            profile_str = self.compile_apparmor_profile(agent_id, capabilities)
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".aa",
                prefix=f"securenet-{hash(agent_id) % 10000:04d}_",
                delete=False,
            )
            tmp.write(profile_str)
            tmp.flush()
            path = tmp.name
            self._apparmor_profile_path = path
            self._compiled_profiles[agent_id] = path
            logger.info(
                "Compiled dynamic AppArmor profile for agent %s → %s (%d bytes)",
                agent_id, path, len(profile_str),
            )
            return path
        except Exception as e:
            logger.error("Failed to compile AppArmor profile: %s", e)
            return None

    def get_seccomp_for_agent(self, agent_id: str) -> Optional[str]:
        """Get compiled seccomp JSON for a specific agent."""
        try:
            from src.identify.identity_registry import IdentityRegistry
            agent = IdentityRegistry.get_agent(agent_id)
            if agent:
                return self.compile_seccomp_profile(
                    agent.get("capabilities", {})
                )
        except Exception:
            pass
        return None

    def get_apparmor_for_agent(self, agent_id: str) -> Optional[str]:
        """Get compiled AppArmor profile for a specific agent.

        Generates and caches the profile.
        """
        if agent_id in self._compiled_profiles:
            return self._compiled_profiles[agent_id]
        try:
            from src.identify.identity_registry import IdentityRegistry
            agent = IdentityRegistry.get_agent(agent_id)
            if agent:
                return self.write_apparmor_profile(
                    agent_id, agent.get("capabilities", {})
                )
        except Exception:
            pass
        return None

    def load_apparmor_for_agent(self, agent_id: str) -> Optional[str]:
        """Compile, write, and attempt to load an AppArmor profile into the kernel.

        Tries `sudo -n apparmor_parser -r <path>`. Returns the profile name
        (e.g., 'securenet-agent-abcd1234') on success, None on failure.

        Graceful fallback: if sudo is not available or parser fails,
        logs a warning and returns None so the caller can use the default
        profile or skip AppArmor entirely.
        """
        path = self.get_apparmor_for_agent(agent_id)
        if not path:
            return None

        agent_hash = str(hash(agent_id))[-8:]
        profile_name = f"securenet-agent-{agent_hash}"

        try:
            result = subprocess.run(
                ["sudo", "-n", "apparmor_parser", "-r", path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                logger.info(
                    "Loaded dynamic AppArmor profile '%s' from %s for agent %s",
                    profile_name, path, agent_id,
                )
                return profile_name

            stderr = result.stderr.strip()[:200]
            logger.warning(
                "apparmor_parser failed for agent %s (exit=%d): %s",
                agent_id, result.returncode, stderr,
            )
            return None

        except FileNotFoundError:
            logger.debug("sudo or apparmor_parser not found — skipping dynamic AppArmor for agent %s", agent_id)
            return None
        except subprocess.TimeoutExpired:
            logger.warning("apparmor_parser timed out for agent %s", agent_id)
            return None
        except PermissionError:
            logger.debug("Insufficient permissions to load AppArmor for agent %s", agent_id)
            return None

    def cleanup(self, agent_id: Optional[str] = None):
        if agent_id and agent_id in self._compiled_profiles:
            path = self._compiled_profiles.pop(agent_id)
            try:
                Path(path).unlink(missing_ok=True)
            except Exception:
                pass
        elif agent_id is None:
            for path in list(self._compiled_profiles.values()):
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass
            self._compiled_profiles.clear()


_profile_compiler: Optional[DynamicProfileCompiler] = None


def get_profile_compiler() -> DynamicProfileCompiler:
    global _profile_compiler
    if _profile_compiler is None:
        _profile_compiler = DynamicProfileCompiler()
    return _profile_compiler

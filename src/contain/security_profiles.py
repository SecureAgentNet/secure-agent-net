import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger("SecureAgentNet.Contain.SecurityProfiles")


SECCOMP_DEFAULT = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
    "syscalls": [
        {
            "names": [
                "accept", "accept4", "access", "arch_prctl", "bind", "brk",
                "capget", "capset", "chdir", "chmod", "chown",
                "clock_gettime", "clone", "close", "connect",
                "dup", "dup2", "epoll_create", "epoll_ctl",
                "epoll_pwait", "epoll_wait", "exit", "exit_group",
                "faccessat", "fchmod", "fchown", "fcntl", "fstat",
                "futex", "getdents64", "getegid", "geteuid", "getgid",
                "getpid", "getrandom", "getuid", "ioctl", "listen",
                "lseek", "mmap", "mprotect", "munmap", "nanosleep",
                "newfstatat", "openat", "pipe2", "poll", "prctl",
                "pread64", "pselect6", "pwrite64", "read", "readlink",
                "recvfrom", "recvmsg", "rseq", "rt_sigaction",
                "rt_sigprocmask", "rt_sigreturn", "sched_getaffinity",
                "select", "sendmmsg", "sendto", "set_robust_list",
                "setitimer", "setsockopt", "socket", "splice", "stat",
                "sysinfo", "tgkill", "uname", "wait4", "write", "writev",
            ],
            "action": "SCMP_ACT_ALLOW",
        },
        {
            "names": ["personality"],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {"index": 0, "value": 0, "op": "SCMP_CMP_EQ"},
            ],
        },
    ],
}

APPARMOR_DEFAULT = """
#include <tunables/global>

profile securenet-agent flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Read-only root filesystem
  / r,
  /usr/** r,
  /lib/** r,
  /lib64/** r,
  /etc/** r,
  /opt/** r,

  # Writable directories
  /tmp/** rw,
  /var/tmp/** rw,

  # Deny sensitive paths
  deny /proc/sys/** w,
  deny /sys/** w,
  deny /boot/** rwx,
  deny /root/** rwx,
  deny /etc/shadow rwx,
  deny /etc/sudoers rwx,
  deny /etc/ssh/** rwx,

  # Network
  network inet tcp,
  network inet udp,
  deny network inet raw,
  deny network packet,
  deny network netlink,

  # Capabilities (all dropped)
  deny capability *,
}
"""


class SeccompProfileManager:
    def __init__(self):
        self._profile_path = Path(__file__).parent.parent.parent / "config" / "seccomp_profile.json"

    def load_profile(self) -> Optional[str]:
        try:
            with open(self._profile_path, "r") as f:
                return json.dumps(json.load(f))
        except FileNotFoundError:
            logger.warning("Seccomp profile not found. Using built-in default.")
            return json.dumps(SECCOMP_DEFAULT)

    def get_profile_dict(self) -> Dict[str, Any]:
        try:
            with open(self._profile_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return SECCOMP_DEFAULT


class AppArmorProfileManager:
    @staticmethod
    def get_profile() -> str:
        return APPARMOR_DEFAULT

    @staticmethod
    def write_profile(path: Path) -> bool:
        try:
            path.write_text(APPARMOR_DEFAULT)
            return True
        except Exception as e:
            logger.error(f"Failed to write AppArmor profile: {e}")
            return False

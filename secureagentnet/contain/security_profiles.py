import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from secureagentnet.contain.runtime_syscalls import GENERAL_RUNTIME_SYSCALLS

logger = logging.getLogger("SecureAgentNet.Contain.SecurityProfiles")


SECCOMP_DEFAULT = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
    "syscalls": [
        {
            # The general-purpose fallback, used when no per-agent profile
            # applies, so it carries sockets too. Per-agent profiles start from
            # the socket-free base and add network syscalls per capability.
            # Both derive from the same source, so a syscall required just to
            # start a process cannot go missing from one of them. Dangerous
            # syscalls are absent and therefore denied by defaultAction.
            "names": list(GENERAL_RUNTIME_SYSCALLS),
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

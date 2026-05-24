import os
import sys
import shutil
from enum import Enum
from pathlib import Path


class Platform(str, Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"


def detect_platform() -> Platform:
    if sys.platform == "win32":
        return Platform.WINDOWS
    if sys.platform == "darwin":
        return Platform.MACOS
    return Platform.LINUX


def docker_available() -> bool:
    return shutil.which("docker") is not None or _docker_desktop_socket() is not None


def docker_socket_path() -> str | None:
    """Return the Docker socket path for the current platform."""
    sock = _docker_desktop_socket()
    if sock:
        return sock
    if detect_platform() == Platform.LINUX:
        default = "/var/run/docker.sock"
        return default if os.path.exists(default) else None
    return None


def _docker_desktop_socket() -> str | None:
    """Detect Docker Desktop socket for macOS and Windows."""
    platform = detect_platform()
    if platform == Platform.MACOS:
        candidates = [
            os.path.expanduser("~/.docker/run/docker.sock"),
            "/var/run/docker.sock",
            "/run/docker.sock",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None
    if platform == Platform.WINDOWS:
        pipe = "//./pipe/docker_engine"
        return pipe if os.path.exists(pipe) else None
    return None


def docker_engine_running() -> bool:
    """Check if Docker daemon is responsive."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def apparmor_available() -> bool:
    if detect_platform() != Platform.LINUX:
        return False
    return shutil.which("apparmor_parser") is not None


def ollama_available() -> bool:
    return shutil.which("ollama") is not None


def redis_available() -> bool:
    if shutil.which("redis-cli") is not None:
        return True
    if detect_platform() == Platform.WINDOWS:
        return shutil.which("redis-server") is not None
    return False


def safe_path(*parts: str) -> str:
    return str(Path(*parts))


def platform_name() -> str:
    plat = detect_platform()
    match plat:
        case Platform.LINUX:
            return "Linux"
        case Platform.MACOS:
            return "macOS"
        case Platform.WINDOWS:
            return "Windows"

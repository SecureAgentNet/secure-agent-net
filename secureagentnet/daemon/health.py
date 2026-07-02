"""Per-service health probes for the SecureAgentNet daemon.

Each probe is bounded (short socket timeouts) and fail-safe — a probe that errors
reports the service as offline rather than raising. Results feed the desktop and
cloud System-Health panels.
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse
from typing import Dict


def _tcp_ok(url: str, default_port: int, timeout: float = 1.0) -> bool:
    try:
        u = urlparse(url if "//" in url else "//" + url)
        host = u.hostname or "127.0.0.1"
        port = u.port or default_port
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _database_ok() -> bool:
    try:
        from sqlalchemy import text
        from secureagentnet.database.connection import get_session_local
        session = get_session_local()()
        try:
            session.execute(text("SELECT 1"))
            return True
        finally:
            session.close()
    except Exception:
        return False


def _docker_ok() -> bool:
    try:
        from secureagentnet.utils.platform import docker_socket_path, docker_available
        sock = docker_socket_path()
        if sock and sock.startswith("/"):
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(1.0)
            try:
                c.connect(sock)
                return True
            finally:
                c.close()
        return docker_available()
    except Exception:
        return False


def probe_services() -> Dict[str, str]:
    """Return {service_label: "online" | "offline"} for the core dependencies."""
    try:
        from secureagentnet.core.config import get_settings
        st = get_settings()
        vault_addr = st.vault_addr
        ollama_url = st.ollama_api_url
    except Exception:
        vault_addr, ollama_url = "http://127.0.0.1:8200", "http://127.0.0.1:11434"

    def mark(ok: bool) -> str:
        return "online" if ok else "offline"

    return {
        "Database": mark(_database_ok()),
        "Vault": mark(_tcp_ok(vault_addr, 8200)),
        "Ollama LLM": mark(_tcp_ok(ollama_url, 11434)),
        "Docker": mark(_docker_ok()),
        # The MCP gateway is served by this daemon process — if this responds, it is up.
        "MCP Gateway": "online",
    }

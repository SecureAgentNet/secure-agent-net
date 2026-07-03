"""Per-service health probes for the SecureAgentNet daemon.

Each probe is bounded (short socket timeouts) and fail-safe — a probe that errors
reports the service as offline rather than raising. Results feed the desktop and
cloud System-Health panels.
"""
from __future__ import annotations

import os
import socket
import urllib.error
import urllib.request
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


def _http_ok(url: str, timeout: float = 1.5) -> bool:
    """True if an HTTP server actually answers at ``url``.

    Stronger than a raw TCP connect: a container can publish a port while the app
    inside has crashed on startup, accepting the TCP handshake and then resetting
    the HTTP request. Any real HTTP status (even 401/404/405) counts as online;
    a connection reset/refused/timeout counts as offline.
    """
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 600
    except urllib.error.HTTPError:
        # The server responded with an HTTP error code — it is alive.
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

    # The MCP gateway is served by the SecureAgentNet API server (main.py mounts
    # mcp_router), which listens on port 5000 by default and is a separate process/
    # container from this daemon. Probe it at the HTTP level: the gateway is often a
    # published Docker port, which can accept a TCP connection even when the app
    # inside has crashed on startup — a TCP-only check would falsely report "online".
    mcp_url = os.environ.get("SAN_MCP_GATEWAY_URL", "http://127.0.0.1:5000/")

    return {
        "Database": mark(_database_ok()),
        "Vault": mark(_tcp_ok(vault_addr, 8200)),
        "Ollama LLM": mark(_tcp_ok(ollama_url, 11434)),
        "Docker": mark(_docker_ok()),
        "MCP Gateway": mark(_http_ok(mcp_url)),
    }

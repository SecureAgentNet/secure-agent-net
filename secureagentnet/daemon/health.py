"""Per-service health probes for the SecureAgentNet daemon.

Each probe is bounded (short socket timeouts) and fail-safe — a probe that errors
reports the service as offline rather than raising. Results feed the desktop and
cloud System-Health panels.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from typing import Dict

# A probe result is only as fresh as the slowest dependency it waited on, and the
# desktop polls this several times a minute. Serve a cached snapshot within the TTL
# so a panel refresh never re-pays the probe cost, and a dependency that is *down*
# (the expensive case — each probe burns its full timeout) is retried at a sane rate
# instead of on every poll.
_CACHE_TTL_SECONDS = 10.0
_cache_lock = threading.Lock()
_cached: Dict[str, str] | None = None
_cached_at = 0.0


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


def _probe_services_uncached() -> Dict[str, str]:
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

    # Run the five probes concurrently. Serially, every dependency that is down
    # adds its full timeout to the total (5 down ~= 6s); in parallel the worst case
    # is the slowest single probe (~1.5s).
    probes = {
        "Database": _database_ok,
        "Vault": lambda: _tcp_ok(vault_addr, 8200),
        "Ollama LLM": lambda: _tcp_ok(ollama_url, 11434),
        "Docker": _docker_ok,
        "MCP Gateway": lambda: _http_ok(mcp_url),
    }
    with ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="san-probe") as pool:
        futures = {name: pool.submit(fn) for name, fn in probes.items()}
        results = {}
        for name, fut in futures.items():
            try:
                results[name] = mark(bool(fut.result()))
            except Exception:
                results[name] = "offline"
    return results


def probe_services(max_age: float = _CACHE_TTL_SECONDS) -> Dict[str, str]:
    """Cached wrapper around the live probes.

    Pass ``max_age=0`` to force a fresh probe (the Settings page's explicit
    "re-check now" action); everything else shares the cached snapshot.
    """
    global _cached, _cached_at
    now = time.monotonic()
    with _cache_lock:
        if _cached is not None and max_age > 0 and (now - _cached_at) < max_age:
            return dict(_cached)
    fresh = _probe_services_uncached()
    with _cache_lock:
        _cached = fresh
        _cached_at = time.monotonic()
    return dict(fresh)

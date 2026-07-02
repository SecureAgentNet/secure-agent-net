"""Daemon runtime for the SecureAgentNet desktop engine."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

import uvicorn

from secureagentnet.daemon.api import create_app
from secureagentnet.daemon.config import DaemonSettings, get_daemon_settings

logger = logging.getLogger("SecureAgentNet.Daemon")


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Keep SQLAlchemy quiet unless something is wrong.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def write_pid_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()))


def remove_pid_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


async def _run_uvicorn(settings: DaemonSettings) -> None:
    app = create_app(settings=settings)
    config = uvicorn.Config(
        app,
        host=settings.daemon_host,
        port=settings.daemon_port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    await server.serve()


def run_daemon(settings: Optional[DaemonSettings] = None, daemonize: bool = False) -> None:
    settings = settings or get_daemon_settings()
    _setup_logging()

    if daemonize and sys.platform != "win32":
        _fork_to_background()

    write_pid_file(settings.pid_file)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Handle signals gracefully.
    def _on_signal(sig: int) -> None:
        logger.info("Received signal %s, shutting down", sig)
        for task in asyncio.all_tasks(loop):
            task.cancel()

    if sys.platform != "win32":
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            loop.add_signal_handler(sig, lambda s=sig: _on_signal(s))

    try:
        logger.info(
            "Starting SecureAgentNet daemon on %s:%s",
            settings.daemon_host,
            settings.daemon_port,
        )
        loop.run_until_complete(_run_uvicorn(settings))
    except asyncio.CancelledError:
        logger.info("Daemon cancelled")
    finally:
        remove_pid_file(settings.pid_file)
        loop.close()


def _fork_to_background() -> None:
    """Double-fork to detach from the controlling terminal on Unix."""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        logger.error("First fork failed: %s", exc)
        sys.exit(1)

    os.chdir(str(Path.home()))
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        logger.error("Second fork failed: %s", exc)
        sys.exit(1)

    # Redirect standard file descriptors to /dev/null.
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(devnull, sys.stdout.fileno())
    os.dup2(devnull, sys.stderr.fileno())
    os.close(devnull)


if __name__ == "__main__":
    run_daemon()

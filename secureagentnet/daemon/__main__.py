"""Entry point: python -m secureagentnet.daemon.daemon"""
from __future__ import annotations

import argparse

from secureagentnet.daemon.daemon import run_daemon
from secureagentnet.daemon.config import get_daemon_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureAgentNet background engine")
    parser.add_argument("--daemonize", action="store_true", help="Detach from terminal (Unix only)")
    args = parser.parse_args()
    run_daemon(settings=get_daemon_settings(), daemonize=args.daemonize)


if __name__ == "__main__":
    main()

"""Run the Cloud Console backend: ``secureagentnet-cloud`` or ``python -m secureagentnet.cloud``."""
from __future__ import annotations

import argparse
import logging

import uvicorn

from secureagentnet.cloud.config import get_cloud_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureAgentNet Cloud Console backend")
    parser.add_argument("--host", default=None, help="Override bind host")
    parser.add_argument("--port", type=int, default=None, help="Override bind port")
    parser.add_argument("--reload", action="store_true", help="Auto-reload (development)")
    parser.add_argument("--migrate", action="store_true",
                        help="Run DB migrations (alembic upgrade head) and exit — "
                             "use as a deploy/CI step before starting the server")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    settings = get_cloud_settings()

    if args.migrate:
        from secureagentnet.cloud.db import run_migrations
        run_migrations()
        logging.getLogger("SecureAgentNet.Cloud").info("Migrations applied. Exiting.")
        return

    uvicorn.run(
        "secureagentnet.cloud.app:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=args.reload,
        access_log=False,
    )


if __name__ == "__main__":
    main()

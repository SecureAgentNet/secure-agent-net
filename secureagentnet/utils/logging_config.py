"""Application logging configuration.

Production log aggregators (Loki, CloudWatch, Datadog, ELK) want one JSON object
per line on stdout, not free-form text. This module provides a structured JSON
formatter and a single `configure_logging()` entry point driven by env vars so
the format is a deployment concern, not a code change:

    LOG_FORMAT = json | text   (default: text; set json in containers/prod)
    LOG_LEVEL  = DEBUG | INFO | WARNING | ...   (default: INFO)

The JSON formatter emits a stable base schema (timestamp, level, logger,
message) plus any structured fields attached via ``logger.info(..., extra={...})``
and full exception tracebacks, so pipeline events stay queryable downstream.
This is deliberately dependency-free (stdlib ``logging`` + ``json``) — no
python-json-logger — to keep the runtime image slim.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import sys

# logging.LogRecord attributes that are metadata, not caller-supplied fields.
# Anything on the record NOT in here is treated as a structured `extra` field.
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}


class JsonFormatter(logging.Formatter):
    """Render each record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Structured fields passed via logger.<level>(..., extra={...}).
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str)


def configure_logging(force: bool = False) -> None:
    """Configure the root logger from ``LOG_FORMAT`` / ``LOG_LEVEL`` env vars.

    Idempotent: replaces the root handler so it is safe to call at process start
    (and again under reload) without stacking duplicate handlers.
    """
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("LOG_FORMAT", "text").lower()

    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))

    root = logging.getLogger()
    if root.handlers and not force:
        # Respect an already-configured root unless explicitly forced.
        root.setLevel(level)
        return
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

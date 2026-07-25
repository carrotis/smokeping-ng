"""Structured JSON logging.

One line of JSON per event, on stdout, so that whatever collects container
logs (Loki, Vector, CloudWatch, ...) gets structured fields for free.

Usage::

    from smokecommon.logging import get_logger, setup_logging

    setup_logging(level="INFO", service="smoke-agent")
    log = get_logger(__name__)
    log.info("probe finished", extra={"target": "8.8.8.8", "latency_ms": 12.3})

Anything passed via ``extra=`` becomes a top-level JSON key.
"""

from __future__ import annotations

import json
import logging
import sys
import traceback
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

#: Fields every LogRecord carries; anything else the caller attached via
#: ``extra=`` is emitted as a structured field.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

#: Bound to a request/cycle so every log line inside it is correlatable.
#: Default is None rather than {} -- a shared mutable default on a ContextVar
#: is the kind of thing that works until someone mutates it in place.
_log_context: ContextVar[dict[str, Any] | None] = ContextVar(
    "smoke_log_context", default=None
)


def get_log_context() -> dict[str, Any]:
    return _log_context.get() or {}


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single JSON object."""

    def __init__(self, service: str = "smoke", static_fields: dict[str, Any] | None = None):
        super().__init__()
        self.service = service
        self.static_fields = static_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(self.static_fields)

        ctx = get_log_context()
        if ctx:
            payload.update(ctx)

        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            payload["error"] = {
                "type": getattr(exc_type, "__name__", str(exc_type)),
                "message": str(exc_value),
                "stack": "".join(traceback.format_exception(exc_type, exc_value, exc_tb))[-4000:],
            }

        return json.dumps(payload, default=_fallback, ensure_ascii=False)


def _fallback(obj: Any) -> str:
    """Last-resort serialiser so a stray object never kills a log line."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return repr(obj)


class PlainFormatter(logging.Formatter):
    """Human-friendly formatter for interactive use (``--log-format=text``)."""

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            k: v for k, v in record.__dict__.items() if k not in _RESERVED and not k.startswith("_")
        }
        extras.update(get_log_context())
        if extras:
            rendered = " ".join(f"{k}={v}" for k, v in extras.items())
            base = f"{base} | {rendered}"
        return base


def setup_logging(
    level: str = "INFO",
    service: str = "smoke",
    fmt: str = "json",
    static_fields: dict[str, Any] | None = None,
) -> None:
    """Install a single stdout handler on the root logger.

    Idempotent: calling it twice replaces the handler instead of duplicating
    output (which matters because uvicorn also touches logging config).
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(
        JsonFormatter(service=service, static_fields=static_fields)
        if fmt == "json"
        else PlainFormatter()
    )
    root.addHandler(handler)
    root.setLevel(level.upper())

    # uvicorn installs its own handlers; make them propagate to ours instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True

    # httpx logs every request at INFO, which is far too chatty for an agent
    # that ships a batch every few seconds.
    logging.getLogger("httpx").setLevel("WARNING")
    logging.getLogger("httpcore").setLevel("WARNING")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class bind_context:
    """Context manager that adds fields to every log line inside the block.

    ::

        with bind_context(target="8.8.8.8", probe="ping"):
            log.info("starting")   # -> includes target and probe
    """

    def __init__(self, **fields: Any) -> None:
        self.fields = fields
        self._token = None

    def __enter__(self) -> bind_context:
        merged = {**get_log_context(), **self.fields}
        self._token = _log_context.set(merged)
        return self

    def __exit__(self, *exc: object) -> None:
        if self._token is not None:
            _log_context.reset(self._token)

"""Structured logging built on structlog.

Configures Python's stdlib logging to render through structlog so every log
line is either human-readable Rich text (interactive) or a single JSON object
(machine ingestion). Plain ``logging.getLogger()`` call sites keep working and
render through the same pipeline (stdlib interop), so third-party libraries and
other code do not need to know about structlog.

Context fields (``campaign_id``, ``phase``, ``vector_id``) are bound via
``structlog.contextvars`` by the scanner layers and merged into every line
emitted within that context. See :mod:`ziran.infrastructure.logging.context`.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Literal

import structlog
from rich.console import Console
from rich.logging import RichHandler

LogFormat = Literal["json", "text"]

# Shared processors applied to both structlog-native and foreign (stdlib) records.
_SHARED_PROCESSORS: list[Any] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]


def _resolve_format(log_format: LogFormat | None) -> LogFormat:
    """Resolve the effective format: explicit choice, else TTY autodetect."""
    if log_format is not None:
        return log_format
    return "text" if sys.stderr.isatty() else "json"


def _build_handler(fmt: LogFormat, level: str, rich_tracebacks: bool) -> logging.Handler:
    """Build the console handler for the chosen format."""
    handler: logging.Handler
    if fmt == "json":
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.processors.JSONRenderer(),
                foreign_pre_chain=_SHARED_PROCESSORS,
            )
        )
    else:
        handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=True,
            rich_tracebacks=rich_tracebacks,
            tracebacks_show_locals=False,
            markup=True,
        )
        handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.dev.ConsoleRenderer(colors=False),
                foreign_pre_chain=_SHARED_PROCESSORS,
            )
        )
    handler.setLevel(level)
    return handler


def setup_logging(
    level: str = "INFO",
    rich_tracebacks: bool = True,
    log_file: str | None = None,
    log_format: LogFormat | None = None,
) -> None:
    """Configure structured logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        rich_tracebacks: Use Rich for formatted tracebacks (text mode only).
        log_file: Optional path to a log file for persistent output.
        log_format: ``"json"`` or ``"text"``. When ``None`` (default), resolves
            to ``"text"`` on an interactive TTY and ``"json"`` otherwise.
    """
    fmt = _resolve_format(log_format)

    structlog.configure(
        processors=[
            *_SHARED_PROCESSORS,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(_build_handler(fmt, level, rich_tracebacks))

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.processors.JSONRenderer(),
                foreign_pre_chain=_SHARED_PROCESSORS,
            )
        )
        root_logger.addHandler(file_handler)

    logging.getLogger("ziran").setLevel(level)

    # Quiet noisy third-party loggers.
    for noisy_logger in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a named structlog logger within the ``ziran`` namespace.

    Args:
        name: Logger name (prefixed with ``ziran.`` if not already).

    Returns:
        A bound structlog logger. Call sites emit an event name plus keyword
        fields, e.g. ``logger.info("attack_failed", vector_id=vid, error=str(e))``.
    """
    if not name.startswith("ziran."):
        name = f"ziran.{name}"
    return structlog.stdlib.get_logger(name)

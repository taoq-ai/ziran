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
from typing import Any, Literal, cast

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


# Library default: stdlib logging behind a plain console renderer, used only while the host
# has not configured structlog. It is applied per logger, never through structlog.configure,
# so a host's later configure (partial or guarded by is_configured) behaves as without ziran.
_LIBRARY_DEFAULT: dict[str, Any] = {
    "processors": [
        structlog.stdlib.filter_by_level,
        *_SHARED_PROCESSORS,
        structlog.dev.ConsoleRenderer(
            colors=False, exception_formatter=structlog.dev.plain_traceback
        ),
    ],
    "wrapper_class": structlog.stdlib.BoundLogger,
}


class _LibraryLogger:
    """Resolve the logger on each call: the host's structlog config once one exists.

    Unconfigured structlog prints every event, debug included, to stdout. Until the host (or
    ``setup_logging``) configures structlog, events go through stdlib logging instead: nothing
    below WARNING without a handler, WARNING and above on stderr through the last-resort handler.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr: str) -> Any:
        if structlog.is_configured():
            return getattr(structlog.stdlib.get_logger(self._name), attr)
        return getattr(
            structlog.wrap_logger(logging.getLogger(self._name), **_LIBRARY_DEFAULT), attr
        )


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
    return cast("structlog.stdlib.BoundLogger", _LibraryLogger(name))

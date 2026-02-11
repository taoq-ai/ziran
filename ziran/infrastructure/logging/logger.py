"""Structured logging with Rich handler.

Configures Python's stdlib logging to use Rich for beautiful
terminal output with color, formatting, and structured context.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(
    level: str = "INFO",
    rich_tracebacks: bool = True,
    log_file: str | None = None,
) -> None:
    """Configure structured logging with Rich for terminal output.

    Sets up the root logger with a Rich handler for beautiful terminal
    output. Optionally adds a file handler for persistent logs.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        rich_tracebacks: Use Rich for formatted tracebacks.
        log_file: Optional path to a log file for persistent output.
    """
    console = Console(stderr=True)

    # Rich handler for terminal output
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=True,
        rich_tracebacks=rich_tracebacks,
        tracebacks_show_locals=False,
        markup=True,
    )
    rich_handler.setLevel(level)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to prevent duplicate output
    root_logger.handlers.clear()
    root_logger.addHandler(rich_handler)

    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Set koan logger
    ziran_logger = logging.getLogger("ziran")
    ziran_logger.setLevel(level)

    # Quiet noisy third-party loggers
    for noisy_logger in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger within the koan namespace.

    Args:
        name: Logger name (will be prefixed with 'ziran.').

    Returns:
        Configured logger instance.
    """
    if not name.startswith("ziran."):
        name = f"ziran.{name}"
    return logging.getLogger(name)

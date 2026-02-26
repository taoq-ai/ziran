"""Tests for the structured logging module."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from ziran.infrastructure.logging.logger import get_logger, setup_logging


class TestSetupLogging:
    """Tests for setup_logging()."""

    def test_basic_setup(self) -> None:
        """Root logger should be configured after setup."""
        setup_logging(level="WARNING")
        root = logging.getLogger()
        assert root.level == logging.WARNING
        assert len(root.handlers) >= 1

    def test_debug_level(self) -> None:
        """Debug level should propagate to the root logger."""
        setup_logging(level="DEBUG")
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_log_file(self) -> None:
        """When log_file is given, a FileHandler should be added."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name

        setup_logging(level="INFO", log_file=path)
        root = logging.getLogger()

        file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1

        # Write a log message and verify it reaches the file
        test_logger = logging.getLogger("ziran.test")
        test_logger.info("hello from test")

        for h in file_handlers:
            h.flush()

        content = Path(path).read_text()
        assert "hello from test" in content

        # Cleanup
        Path(path).unlink(missing_ok=True)

    def test_noisy_loggers_suppressed(self) -> None:
        """Third-party noisy loggers should be set to WARNING."""
        setup_logging(level="DEBUG")
        for name in ("httpx", "httpcore", "urllib3", "asyncio"):
            assert logging.getLogger(name).level == logging.WARNING

    def test_rich_tracebacks_disabled(self) -> None:
        """Should accept rich_tracebacks=False without error."""
        setup_logging(level="INFO", rich_tracebacks=False)
        root = logging.getLogger()
        assert len(root.handlers) >= 1


class TestGetLogger:
    """Tests for get_logger()."""

    def test_prefixes_name(self) -> None:
        """Names without 'ziran.' prefix should be auto-prefixed."""
        logger = get_logger("scanner")
        assert logger.name == "ziran.scanner"

    def test_already_prefixed(self) -> None:
        """Names already prefixed with 'ziran.' should not be double-prefixed."""
        logger = get_logger("ziran.scanner")
        assert logger.name == "ziran.scanner"

    def test_returns_logger_instance(self) -> None:
        """Should return a logging.Logger instance."""
        logger = get_logger("test")
        assert isinstance(logger, logging.Logger)

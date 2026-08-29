"""Tests for the structured logging module."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

import pytest
from rich.logging import RichHandler

from ziran.infrastructure.logging.context import bind_campaign, bind_phase, clear_context
from ziran.infrastructure.logging.logger import get_logger, setup_logging


@pytest.fixture(autouse=True)
def _reset_context() -> None:
    clear_context()
    yield
    clear_context()


class TestSetupLogging:
    """Tests for setup_logging()."""

    def test_basic_setup(self) -> None:
        setup_logging(level="WARNING", log_format="json")
        root = logging.getLogger()
        assert root.level == logging.WARNING
        assert len(root.handlers) >= 1

    def test_debug_level(self) -> None:
        setup_logging(level="DEBUG", log_format="json")
        assert logging.getLogger().level == logging.DEBUG

    def test_text_uses_rich_handler(self) -> None:
        setup_logging(level="INFO", log_format="text")
        root = logging.getLogger()
        assert any(isinstance(h, RichHandler) for h in root.handlers)

    def test_json_line_is_valid_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A JSON-mode log line must parse and carry the required base fields."""
        setup_logging(level="INFO", log_format="json")
        get_logger("scanner").info("scan_started", campaign_id="c1")
        line = capsys.readouterr().err.strip().splitlines()[-1]
        record = json.loads(line)
        assert record["event"] == "scan_started"
        assert record["level"] == "info"
        assert record["logger"] == "ziran.scanner"
        assert record["campaign_id"] == "c1"
        assert "timestamp" in record

    def test_bound_context_appears_in_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        setup_logging(level="INFO", log_format="json")
        bind_campaign("camp42")
        bind_phase("exploitation")
        get_logger("phase").info("phase_started")
        record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert record["campaign_id"] == "camp42"
        assert record["phase"] == "exploitation"

    def test_stdlib_interop(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Plain stdlib loggers render through the same JSON pipeline."""
        setup_logging(level="INFO", log_format="json")
        logging.getLogger("ziran.legacy").info("plain message")
        record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert record["event"] == "plain message"
        assert record["logger"] == "ziran.legacy"

    def test_log_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name

        setup_logging(level="INFO", log_file=path, log_format="json")
        logging.getLogger("ziran.test").info("hello from test")
        for h in logging.getLogger().handlers:
            h.flush()

        content = Path(path).read_text()
        assert "hello from test" in content
        Path(path).unlink(missing_ok=True)

    def test_noisy_loggers_suppressed(self) -> None:
        setup_logging(level="DEBUG", log_format="json")
        for name in ("httpx", "httpcore", "urllib3", "asyncio"):
            assert logging.getLogger(name).level == logging.WARNING

    def test_rich_tracebacks_disabled(self) -> None:
        setup_logging(level="INFO", rich_tracebacks=False, log_format="text")
        assert len(logging.getLogger().handlers) >= 1


class TestGetLogger:
    """Tests for get_logger()."""

    def test_prefixes_name(self, capsys: pytest.CaptureFixture[str]) -> None:
        setup_logging(log_format="json")
        get_logger("scanner").info("evt")
        record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert record["logger"] == "ziran.scanner"

    def test_already_prefixed(self, capsys: pytest.CaptureFixture[str]) -> None:
        setup_logging(log_format="json")
        get_logger("ziran.scanner").info("evt")
        record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert record["logger"] == "ziran.scanner"

"""Library-mode logging defaults: importing ziran without setup_logging (spec 094).

Each case runs in a fresh interpreter, since structlog's configuration is
process-global and the test session has usually configured it already.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import structlog

from ziran.infrastructure.logging.logger import get_logger


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )


def test_attack_library_prints_nothing_to_stdout() -> None:
    result = _run("from ziran.application.attacks.library import AttackLibrary; AttackLibrary()")
    assert result.stdout == ""
    assert "attack_library_initialized" not in result.stderr


def test_debug_and_info_are_silent_without_a_handler() -> None:
    result = _run(
        "from ziran.infrastructure.logging.logger import get_logger\n"
        "log = get_logger('probe')\n"
        "log.debug('dbg_event')\n"
        "log.info('info_event')\n"
    )
    assert result.stdout == ""
    assert result.stderr == ""


def test_warning_reaches_stderr() -> None:
    result = _run(
        "from ziran.infrastructure.logging.logger import get_logger\n"
        "get_logger('probe').warning('warn_event', key='v1')\n"
    )
    assert result.stdout == ""
    assert "warn_event" in result.stderr
    # The console renderer, not JSON: ``key=v1`` and a bracketed level.
    assert "key=v1" in result.stderr
    assert "[warning" in result.stderr


def test_host_stdlib_logging_receives_ziran_events() -> None:
    result = _run(
        "import logging, sys\n"
        "logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format='%(name)s|%(message)s')\n"
        "from ziran.infrastructure.logging.logger import get_logger\n"
        "get_logger('probe').info('info_event')\n"
    )
    assert result.stdout == ""
    assert "ziran.probe|" in result.stderr
    assert "info_event" in result.stderr


def test_host_structlog_config_is_kept() -> None:
    result = _run(
        "import structlog\n"
        "structlog.configure(processors=[structlog.processors.JSONRenderer()])\n"
        "from ziran.infrastructure.logging.logger import get_logger\n"
        "get_logger('probe').info('info_event')\n"
    )
    assert '"event": "info_event"' in result.stdout


def test_capture_logs_still_captures() -> None:
    with structlog.testing.capture_logs() as logs:
        get_logger("probe").info("captured_event", key="v")
    assert {"event": "captured_event", "key": "v", "log_level": "info"} in logs


def test_setup_logging_after_first_use_gives_structured_json() -> None:
    """A logger used before setup_logging must pick up the CLI's JSON pipeline."""
    result = _run(
        "from ziran.infrastructure.logging.logger import get_logger, setup_logging\n"
        "log = get_logger('probe')\n"
        "log.info('before_setup')\n"
        "setup_logging(log_format='json')\n"
        "log.info('x', k=1)\n"
    )
    record = json.loads(result.stderr.strip().splitlines()[-1])
    assert record["event"] == "x"
    assert record["k"] == 1


def test_markdown_compare_stdout_holds_only_the_table(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "benchmarks" / "two_tier_judging.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "compare",
            "--format",
            "markdown",
            "--json",
            str(tmp_path / "out.json"),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    lines = result.stdout.strip().splitlines()
    assert lines
    assert all(line.startswith("|") for line in lines)

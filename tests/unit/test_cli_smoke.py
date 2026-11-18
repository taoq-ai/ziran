"""CLI smoke tests — verify all commands respond to ``--help``.

Uses Click's CliRunner so no real scanning, adapters, or I/O happens.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.main import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.mark.unit
class TestCLIHelpSmoke:
    """Every top-level command must respond to --help without error."""

    def test_root_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ziran" in result.output.lower() or "usage" in result.output.lower()

    def test_scan_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--framework" in result.output or "--target" in result.output

    def test_discover_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["discover", "--help"])
        assert result.exit_code == 0

    def test_report_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0

    def test_poc_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["poc", "--help"])
        assert result.exit_code == 0

    def test_policy_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["policy", "--help"])
        assert result.exit_code == 0

    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0


@pytest.mark.unit
class TestCLIScanOptions:
    """Verify new timeout CLI options are registered."""

    def test_attack_timeout_in_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--attack-timeout" in result.output

    def test_phase_timeout_in_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--phase-timeout" in result.output


@pytest.mark.unit
class TestUIMovedStub:
    """Spec 083: ``ziran ui`` is a hidden stub for one minor release."""

    @pytest.mark.parametrize("args", [[], ["--host", "0.0.0.0", "--port", "8484", "--dev"]])
    def test_ui_prints_moved_notice_and_exits_2(self, runner: CliRunner, args: list[str]) -> None:
        result = runner.invoke(cli, ["ui", *args])
        assert result.exit_code == 2
        text = " ".join(result.output.split())
        for needle in ("ZIRAN Cloud", "ZIRAN Enterprise", "info@taoq.ai", "v0.42.0", "Apache-2.0"):
            assert needle in text

    def test_ui_hidden_from_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert not any(line.split()[:1] == ["ui"] for line in result.output.splitlines())

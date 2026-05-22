"""Unit tests for the ``ziran init`` CLI command."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from ziran.interfaces.cli.init_command import init


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.mark.unit
class TestInitInteractive:
    """US1: Interactive project initialization."""

    def test_inprocess_langchain(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                init,
                input="in-process\nlangchain\n",
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            assert "Configuration created" in result.output

    def test_remote_rest(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                init,
                input="remote\nrest\n",
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            config = Path("ziran.yaml")
            assert config.exists()
            content = yaml.safe_load(config.read_text())
            assert content["target"] == "./target.yaml"
            assert content["coverage"] == "standard"

    def test_inprocess_crewai(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                init,
                input="in-process\ncrewai\n",
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            content = yaml.safe_load(Path("ziran.yaml").read_text())
            assert content["framework"] == "crewai"
            assert content["agent_path"] == "./my_agent.py"

    def test_generated_yaml_is_valid(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(
                init,
                input="in-process\nlangchain\n",
                catch_exceptions=False,
            )
            content = yaml.safe_load(Path("ziran.yaml").read_text())
            assert "phases" in content
            assert isinstance(content["phases"], list)
            assert len(content["phases"]) == 8

    def test_next_steps_panel_shown(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                init,
                input="in-process\nlangchain\n",
                catch_exceptions=False,
            )
            assert "Next steps" in result.output
            assert "ziran scan" in result.output


@pytest.mark.unit
class TestInitOverwriteProtection:
    """US2: Overwrite protection."""

    def test_confirm_overwrite_decline(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            Path("ziran.yaml").write_text("original: true\n")
            result = runner.invoke(
                init,
                input="n\n",
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            assert "preserved" in result.output
            content = Path("ziran.yaml").read_text()
            assert "original: true" in content

    def test_confirm_overwrite_accept(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            Path("ziran.yaml").write_text("original: true\n")
            result = runner.invoke(
                init,
                input="y\nin-process\nlangchain\n",
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            content = Path("ziran.yaml").read_text()
            assert "original: true" not in content
            assert "framework" in content


@pytest.mark.unit
class TestInitNonInteractive:
    """US3: Non-interactive mode for CI."""

    def test_non_interactive_generates_config(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                init,
                ["--non-interactive"],
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            content = yaml.safe_load(Path("ziran.yaml").read_text())
            assert content["framework"] == "langchain"
            assert content["coverage"] == "standard"

    def test_non_interactive_refuses_overwrite(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            Path("ziran.yaml").write_text("existing: true\n")
            result = runner.invoke(
                init,
                ["--non-interactive"],
                catch_exceptions=False,
            )
            assert result.exit_code == 1
            assert "already exists" in result.output

    def test_yaml_has_comments(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(
                init,
                ["--non-interactive"],
                catch_exceptions=False,
            )
            raw = Path("ziran.yaml").read_text()
            assert "# ZIRAN Configuration" in raw
            assert "# Coverage level" in raw

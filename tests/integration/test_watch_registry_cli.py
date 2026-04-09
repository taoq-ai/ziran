"""Integration test for the watch-registry CLI command."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from ziran.domain.entities.registry import ManifestSnapshot, ToolDescriptor
from ziran.interfaces.cli.watch_registry import watch_registry


@pytest.mark.integration
class TestWatchRegistryCli:
    """End-to-end tests using Click's CliRunner."""

    def _setup_scenario(self, tmp_path: Path) -> tuple[Path, Path, Path]:
        """Create a config file and a pre-stored snapshot with known drift.

        Returns (config_path, snapshot_dir, output_dir).
        """
        snapshot_dir = tmp_path / "snapshots"
        snapshot_dir.mkdir()
        output_dir = tmp_path / "reports"

        # Store a baseline snapshot
        baseline = ManifestSnapshot(
            server_name="demo-server",
            fetched_at=datetime(2025, 1, 1, tzinfo=UTC),
            tools=[
                ToolDescriptor(name="weather_lookup", description="Safe weather lookup"),
                ToolDescriptor(name="calculator", description="Math calculator"),
            ],
        )
        snapshot_path = snapshot_dir / "demo-server.json"
        snapshot_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")

        # Write a config YAML referencing a server that would fail to connect
        # (we test that the CLI handles connection errors gracefully)
        config = {
            "servers": [
                {
                    "name": "demo-server",
                    "url": "http://127.0.0.1:19999",
                    "transport": "streamable-http",
                }
            ],
            "allowlist": ["weather-lookup", "calculator-server"],
            "exemptions": [],
        }
        config_path = tmp_path / "registry.yml"
        config_path.write_text(yaml.dump(config), encoding="utf-8")

        return config_path, snapshot_dir, output_dir

    def test_cli_handles_unreachable_server(self, tmp_path: Path) -> None:
        """CLI should run without crashing when servers are unreachable."""
        config_path, snapshot_dir, output_dir = self._setup_scenario(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            watch_registry,
            [
                "--config",
                str(config_path),
                "--snapshot-dir",
                str(snapshot_dir),
                "--out",
                str(output_dir),
                "--format",
                "json",
            ],
        )

        # Should not crash — exit code 0 means no critical findings
        assert result.exit_code == 0
        # Report should exist
        report = output_dir / "registry-watch-report.json"
        assert report.exists()

    def test_cli_produces_json_report(self, tmp_path: Path) -> None:
        """The JSON report should be valid JSON with a list structure."""
        config_path, snapshot_dir, output_dir = self._setup_scenario(tmp_path)
        runner = CliRunner()

        runner.invoke(
            watch_registry,
            [
                "--config",
                str(config_path),
                "--snapshot-dir",
                str(snapshot_dir),
                "--out",
                str(output_dir),
                "--format",
                "json",
            ],
        )

        report = output_dir / "registry-watch-report.json"
        data = json.loads(report.read_text(encoding="utf-8"))
        assert isinstance(data, list)

    def test_cli_markdown_format(self, tmp_path: Path) -> None:
        """The markdown report should be written when --format markdown is used."""
        config_path, snapshot_dir, output_dir = self._setup_scenario(tmp_path)
        runner = CliRunner()

        runner.invoke(
            watch_registry,
            [
                "--config",
                str(config_path),
                "--snapshot-dir",
                str(snapshot_dir),
                "--out",
                str(output_dir),
                "--format",
                "markdown",
            ],
        )

        report = output_dir / "registry-watch-report.md"
        assert report.exists()
        content = report.read_text(encoding="utf-8")
        assert "# Registry Watch Report" in content

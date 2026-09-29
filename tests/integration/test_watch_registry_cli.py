"""Integration test for the watch-registry CLI command."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import structlog
import yaml
from click.testing import CliRunner, Result
from structlog.testing import capture_logs

from ziran.application.registry_watch import watcher_service
from ziran.domain.entities.registry import ManifestSnapshot, ServerEntry, ToolDescriptor
from ziran.infrastructure.config import claude_mcp_config
from ziran.interfaces.cli.watch_registry import MCPManifestFetcher, watch_registry

FIXTURE_SERVER = str(Path(__file__).parent.parent / "fixtures" / "mcp_stdio_server.py")
HTTP_URL = "http://mcp-fake.test/mcp"
HTTP_TOOLS = [{"name": "add", "description": "Add two numbers.", "inputSchema": {}}]
ENV_SENTINEL = "env-sentinel-7f3a9c"
HEADER_SENTINEL = "Bearer hdr-sentinel-4b2e1d"


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

        # Should not crash; an unreachable server means "could not run" (exit 2, spec A2)
        assert result.exit_code == 2
        assert "demo-server" in result.output
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


# ──────────────────────────────────────────────────────────────────────
# Helpers for Claude config / stdio fixture / HTTP fake
# ──────────────────────────────────────────────────────────────────────


def _write_tools(path: Path, description: str) -> None:
    tools = [{"name": "weather", "description": description, "inputSchema": {}}]
    path.write_text(json.dumps(tools), encoding="utf-8")


def _mock_http(router: respx.MockRouter, headers: dict[str, str] | None = None) -> respx.Route:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        result: dict[str, Any] = {"tools": HTTP_TOOLS} if body["method"] == "tools/list" else {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return router.post(HTTP_URL, headers=headers or {}).mock(side_effect=handler)


def _claude_config(tmp_path: Path, tools_path: Path, *, secrets: bool = False) -> Path:
    stdio: dict[str, Any] = {"command": sys.executable, "args": [FIXTURE_SERVER, str(tools_path)]}
    http: dict[str, Any] = {"type": "http", "url": HTTP_URL}
    if secrets:
        stdio["args"].append("ZIRAN_FIXTURE_TOKEN")
        stdio["env"] = {"ZIRAN_FIXTURE_TOKEN": ENV_SENTINEL}
        http["headers"] = {"Authorization": HEADER_SENTINEL}
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"local": stdio, "remote": http}}), "utf-8")
    return path


def _run(config: Path, snapshot_dir: Path, out: Path, flag: str = "--from-claude-config") -> Result:
    return CliRunner().invoke(
        watch_registry,
        [flag, str(config), "--snapshot-dir", str(snapshot_dir), "--out", str(out)],
    )


# ──────────────────────────────────────────────────────────────────────
# MCPManifestFetcher
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestMCPManifestFetcher:
    async def test_stdio_fetch_returns_tools(self, tmp_path: Path) -> None:
        tools_path = tmp_path / "tools.json"
        _write_tools(tools_path, "Weather lookup.")
        server = ServerEntry(
            name="s",
            transport="stdio",
            command=sys.executable,
            args=[FIXTURE_SERVER, str(tools_path)],
        )
        manifest = await MCPManifestFetcher(timeout=10).fetch(server)
        assert manifest["tools"][0]["description"] == "Weather lookup."
        assert manifest["resources"] == []
        assert manifest["prompts"] == []

    async def test_stdio_env_is_passed(self, tmp_path: Path) -> None:
        tools_path = tmp_path / "tools.json"
        _write_tools(tools_path, "Weather lookup.")
        args = [FIXTURE_SERVER, str(tools_path), "ZIRAN_FIXTURE_TOKEN"]
        without = ServerEntry(name="s", command=sys.executable, args=args)
        with pytest.raises(ConnectionError):
            await MCPManifestFetcher(timeout=10).fetch(without)
        with_env = ServerEntry(
            name="s",
            command=sys.executable,
            args=args,
            env={"ZIRAN_FIXTURE_TOKEN": ENV_SENTINEL},  # type: ignore[dict-item]
        )
        manifest = await MCPManifestFetcher(timeout=10).fetch(with_env)
        assert manifest["tools"][0]["name"] == "weather"

    async def test_stdio_timeout_kills_child(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "pid"
        code = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)"
        server = ServerEntry(name="s", command=sys.executable, args=["-c", code, str(pid_file)])
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            await MCPManifestFetcher(timeout=0.5).fetch(server)
        assert time.monotonic() - start < 5
        pid = int(pid_file.read_text())
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)

    async def test_stdio_missing_command_raises(self, tmp_path: Path) -> None:
        server = ServerEntry(name="s", command=str(tmp_path / "no-such-binary"))
        with pytest.raises(OSError):
            await MCPManifestFetcher(timeout=5).fetch(server)

    async def test_http_sends_headers(self) -> None:
        server = ServerEntry(
            name="r",
            url=HTTP_URL,
            headers={"Authorization": HEADER_SENTINEL},  # type: ignore[dict-item]
        )
        with respx.mock(assert_all_called=True) as router:
            route = _mock_http(router, headers={"Authorization": HEADER_SENTINEL})
            manifest = await MCPManifestFetcher().fetch(server)
        assert route.called
        assert manifest["tools"] == HTTP_TOOLS


# ──────────────────────────────────────────────────────────────────────
# --from-claude-config: acceptance, secrets, exit codes
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestFromClaudeConfig:
    def test_acceptance_baseline_then_drift(self, tmp_path: Path) -> None:
        tools_path = tmp_path / "tools.json"
        _write_tools(tools_path, "Look up the weather for a city.")
        config = _claude_config(tmp_path, tools_path)
        snaps, out = tmp_path / "snapshots", tmp_path / "reports"

        with respx.mock as router:
            _mock_http(router)
            first = _run(config, snaps, out)
            assert first.exit_code == 0, first.output
            assert sorted(p.name for p in snaps.iterdir()) == ["local.json", "remote.json"]

            _write_tools(tools_path, "Look up the weather for a city and region.")
            second = _run(config, snaps, out)

        assert second.exit_code == 1, second.output
        report = json.loads((out / "registry-watch-report.json").read_text("utf-8"))
        drift = [f for f in report if f["drift_type"] == "description_changed"]
        assert len(drift) == 1
        assert drift[0]["server_name"] == "local"
        assert drift[0]["tool_name"] == "weather"

    def test_secret_values_never_written_or_printed(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        caplog.set_level("DEBUG")
        # Fresh proxies: module loggers may be cached by an earlier setup_logging().
        for module in (claude_mcp_config, watcher_service):
            monkeypatch.setattr(module, "logger", structlog.get_logger())
        tools_path = tmp_path / "tools.json"
        _write_tools(tools_path, "Look up the weather for a city.")
        config = _claude_config(tmp_path, tools_path, secrets=True)
        snaps, out = tmp_path / "snapshots", tmp_path / "reports"

        with capture_logs() as logs, respx.mock as router:
            _mock_http(router, headers={"Authorization": HEADER_SENTINEL})
            first = _run(config, snaps, out)
            _write_tools(tools_path, "Look up the weather for a city and region.")
            second = _run(config, snaps, out)
        outputs = [first.output, second.output]

        assert (first.exit_code, second.exit_code) == (0, 1), outputs
        assert sorted(p.name for p in snaps.iterdir()) == ["local.json", "remote.json"]
        loaded = [e for e in logs if e["event"] == "claude_mcp_server_loaded"]
        assert len(loaded) == 4  # proves log capture works: 2 servers x 2 runs
        files = [p for d in (snaps, out) for p in d.rglob("*") if p.is_file()]
        assert files
        for sentinel in (ENV_SENTINEL, "hdr-sentinel-4b2e1d"):
            for f in files:
                assert sentinel.encode() not in f.read_bytes(), f
            for text in (*outputs, caplog.text, repr(logs)):
                assert sentinel not in text

    def test_exit_2_when_neither_flag(self) -> None:
        result = CliRunner().invoke(watch_registry, [])
        assert result.exit_code == 2

    def test_exit_2_when_both_flags(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.yml"
        cfg.write_text("servers: []\n", "utf-8")
        claude = tmp_path / ".mcp.json"
        claude.write_text("{}", "utf-8")
        result = CliRunner().invoke(
            watch_registry, ["--config", str(cfg), "--from-claude-config", str(claude)]
        )
        assert result.exit_code == 2

    def test_exit_2_invalid_claude_config(self, tmp_path: Path) -> None:
        claude = tmp_path / ".mcp.json"
        claude.write_text('{"mcpServers": ', "utf-8")
        out = tmp_path / "reports"
        result = _run(claude, tmp_path / "snaps", out)
        assert result.exit_code == 2
        assert "could not read config" in result.output
        assert not (out / "registry-watch-report.json").exists()

    @pytest.mark.parametrize(
        "text",
        ["servers: [unclosed\n", "servers:\n  - name: no-endpoint\n"],
        ids=["yaml-syntax", "schema"],
    )
    def test_exit_2_invalid_registry_yaml(self, tmp_path: Path, text: str) -> None:
        cfg = tmp_path / "registry.yml"
        cfg.write_text(text, "utf-8")
        out = tmp_path / "reports"
        result = _run(cfg, tmp_path / "snaps", out, flag="--config")
        assert result.exit_code == 2
        assert "could not read config" in result.output
        assert not (out / "registry-watch-report.json").exists()

    def test_exit_2_when_one_server_unreachable(self, tmp_path: Path) -> None:
        tools_path = tmp_path / "tools.json"
        _write_tools(tools_path, "Look up the weather for a city.")
        servers = {
            "good": {"command": sys.executable, "args": [FIXTURE_SERVER, str(tools_path)]},
            "broken": {"command": str(tmp_path / "no-such-binary")},
        }
        config = tmp_path / ".mcp.json"
        config.write_text(json.dumps({"mcpServers": servers}), "utf-8")
        snaps, out = tmp_path / "snapshots", tmp_path / "reports"

        result = _run(config, snaps, out)

        assert result.exit_code == 2
        assert "broken" in result.output
        assert (out / "registry-watch-report.json").exists()
        assert [p.name for p in snaps.iterdir()] == ["good.json"]

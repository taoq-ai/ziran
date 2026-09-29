"""CLI subcommand for MCP registry drift watching.

Monitors MCP server registries for manifest drift, tool changes,
and typosquat attacks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from ziran import __version__
from ziran.application.registry_watch.watcher_service import emit_findings, watch
from ziran.domain.entities.alerting import AlertConfig
from ziran.domain.entities.registry import DriftFinding, RegistryConfig, ServerEntry
from ziran.infrastructure.alert_sinks.factory import build_sinks
from ziran.infrastructure.config.claude_mcp_config import ClaudeConfigError, load_claude_mcp_config
from ziran.infrastructure.config.env_yaml import EnvVarError, load_yaml_with_env
from ziran.infrastructure.snapshot_stores.json_file_store import JsonFileStore

logger = logging.getLogger(__name__)
console = Console()

# A single tools/list line routinely exceeds asyncio's 64 KiB default.
_STDIO_LINE_LIMIT = 16 * 1024 * 1024
_PROTOCOL_VERSION = "2025-06-18"

# ──────────────────────────────────────────────────────────────────────
# Default manifest fetcher (stdio + HTTP)
# ──────────────────────────────────────────────────────────────────────


async def _rpc(
    proc: asyncio.subprocess.Process, req_id: int, method: str, params: dict[str, Any]
) -> dict[str, Any]:
    """Send one JSON-RPC request over stdio and return its ``result``.

    Errors never echo the server's payload (it may reflect env or args).
    """
    assert proc.stdin is not None and proc.stdout is not None
    request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    proc.stdin.write((json.dumps(request) + "\n").encode())
    await proc.stdin.drain()
    while line := await proc.stdout.readline():
        try:
            msg = json.loads(line)
        except ValueError:
            continue  # server log noise on stdout
        if not isinstance(msg, dict) or msg.get("id") != req_id:
            continue  # notification or unrelated message
        if "error" in msg:
            raise RuntimeError(f"{method} returned a JSON-RPC error")
        result = msg.get("result")
        return result if isinstance(result, dict) else {}
    raise ConnectionError(f"{method}: server closed stdout")


async def _stdio_session(proc: asyncio.subprocess.Process) -> dict[str, Any]:
    assert proc.stdin is not None
    await _rpc(
        proc,
        1,
        "initialize",
        {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ziran", "version": __version__},
        },
    )
    proc.stdin.write(b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n')
    result = await _rpc(proc, 2, "tools/list", {})
    return {"tools": result.get("tools", []), "resources": [], "prompts": []}


class MCPManifestFetcher:
    """Fetch MCP manifests via JSON-RPC 2.0 over stdio (``command``) or HTTP (``url``)."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    async def fetch(self, server: ServerEntry) -> dict[str, Any]:
        if server.command is not None:
            return await self._fetch_stdio(server.command, server)
        return await self._fetch_http(server)

    async def _fetch_stdio(self, command: str, server: ServerEntry) -> dict[str, Any]:
        env = {**os.environ, **{k: v.get_secret_value() for k, v in server.env.items()}}
        proc = await asyncio.create_subprocess_exec(
            command,
            *server.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,  # server diagnostics never reach our output
            env=env,
            limit=_STDIO_LINE_LIMIT,
        )
        try:
            return await asyncio.wait_for(_stdio_session(proc), self._timeout)
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()

    async def _fetch_http(self, server: ServerEntry) -> dict[str, Any]:
        import httpx

        if server.url is None:
            raise ValueError("server has neither 'url' nor 'command'")
        headers = {k: v.get_secret_value() for k, v in server.headers.items()}
        async with httpx.AsyncClient(timeout=self._timeout, headers=headers) as client:
            tools_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
            resp = await client.post(server.url, json=tools_payload)
            resp.raise_for_status()
            tools_result = resp.json().get("result", {})

            resources_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/list",
                "params": {},
            }
            try:
                resp2 = await client.post(server.url, json=resources_payload)
                resp2.raise_for_status()
                resources_result = resp2.json().get("result", {})
            except Exception:
                resources_result = {}

            prompts_payload = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "prompts/list",
                "params": {},
            }
            try:
                resp3 = await client.post(server.url, json=prompts_payload)
                resp3.raise_for_status()
                prompts_result = resp3.json().get("result", {})
            except Exception:
                prompts_result = {}

            return {
                "tools": tools_result.get("tools", []),
                "resources": resources_result.get("resources", []),
                "prompts": prompts_result.get("prompts", []),
            }


# ──────────────────────────────────────────────────────────────────────
# Report helpers
# ──────────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


def _write_json_report(findings: list[DriftFinding], path: Path) -> None:
    data = [f.model_dump(mode="json") for f in findings]
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _write_markdown_report(findings: list[DriftFinding], path: Path) -> None:
    lines = ["# Registry Watch Report\n"]
    if not findings:
        lines.append("No drift detected.\n")
    else:
        lines.append(f"**{len(findings)} finding(s) detected.**\n")
        for f in findings:
            lines.append(f"## {f.drift_type} — {f.server_name}\n")
            lines.append(f"- **Severity:** {f.severity}")
            if f.tool_name:
                lines.append(f"- **Tool:** {f.tool_name}")
            lines.append(f"- **Message:** {f.message}")
            if f.previous_value:
                lines.append(f"- **Previous:** {f.previous_value}")
            if f.current_value:
                lines.append(f"- **Current:** {f.current_value}")
            if f.suspected_canonical:
                lines.append(f"- **Suspected canonical:** {f.suspected_canonical}")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _print_summary(findings: list[DriftFinding]) -> None:
    if not findings:
        console.print("[green]No drift detected.[/green]")
        return

    table = Table(title="Registry Watch Findings")
    table.add_column("Server", style="bold")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Tool")
    table.add_column("Message")

    for f in findings:
        severity_style = _SEVERITY_COLORS.get(f.severity, "")
        table.add_row(
            f.server_name,
            f.drift_type,
            f"[{severity_style}]{f.severity}[/{severity_style}]",
            f.tool_name or "-",
            f.message,
        )

    console.print(table)
    console.print(f"\n[bold]{len(findings)} finding(s) total.[/bold]")


# ──────────────────────────────────────────────────────────────────────
# Click command
# ──────────────────────────────────────────────────────────────────────


def _safe_validation_detail(exc: ValidationError) -> str:
    """Render a pydantic error without input values (``str(exc)`` would include them)."""
    return "; ".join(
        f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
        for e in exc.errors(include_input=False, include_url=False)
    )


def _load_registry_config(
    config_path: Path | None, claude_config_path: Path | None
) -> RegistryConfig:
    """Load the registry config from exactly one source; exit 2 with a safe message on failure."""
    path = claude_config_path or config_path
    assert path is not None
    try:
        if claude_config_path is not None:
            return RegistryConfig(servers=load_claude_mcp_config(claude_config_path))
        # Resolve !env / ${VAR} references for alert secrets.
        raw_config = load_yaml_with_env(path.read_text(encoding="utf-8"))
        return RegistryConfig.model_validate(raw_config)
    except yaml.YAMLError as exc:
        detail = type(exc).__name__  # its text quotes the offending line
    except ValidationError as exc:
        detail = _safe_validation_detail(exc)
    except (OSError, ClaudeConfigError, EnvVarError) as exc:
        detail = str(exc)
    click.echo(f"Error: could not read config {path}: {detail}", err=True)
    raise SystemExit(2)


@click.command("watch-registry")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to registry config YAML file.",
)
@click.option(
    "--from-claude-config",
    "claude_config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Build the registry from a Claude Code MCP config: a project or plugin "
        ".mcp.json, or user settings JSON with mcpServers. Mutually exclusive with --config."
    ),
)
@click.option(
    "--snapshot-dir",
    type=click.Path(path_type=Path),
    default=Path(".ziran/snapshots"),
    show_default=True,
    help="Directory for storing manifest snapshots.",
)
@click.option(
    "--out",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./reports"),
    show_default=True,
    help="Output directory for findings reports.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown"]),
    default="json",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--dry-run-alerts",
    is_flag=True,
    help="Preview alert payloads without contacting Slack/GitHub.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def watch_registry(
    config_path: Path | None,
    claude_config_path: Path | None,
    snapshot_dir: Path,
    output_dir: Path,
    output_format: str,
    dry_run_alerts: bool,
    verbose: bool,
) -> None:
    """Monitor MCP server registries for drift and typosquatting.

    Pass exactly one of --config or --from-claude-config.

    \b
    Exit codes (precedence 2 > 1 > 0):
      0  every server processed, no high/critical finding
      1  every server processed, at least one high/critical finding
      2  could not run completely: usage error, unreadable or invalid
         config, unreachable server or timeout, alert delivery failure
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    if (config_path is None) == (claude_config_path is None):
        raise click.UsageError("pass exactly one of --config or --from-claude-config")
    registry_config = _load_registry_config(config_path, claude_config_path)

    # Override snapshot dir if specified in config
    if registry_config.snapshot_dir:
        snapshot_dir = Path(registry_config.snapshot_dir)

    store = JsonFileStore(snapshot_dir)
    findings, unreachable = asyncio.run(watch(registry_config, store, MCPManifestFetcher()))

    # Write report
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = "json" if output_format == "json" else "md"
    report_path = output_dir / f"registry-watch-report.{ext}"

    if output_format == "json":
        _write_json_report(findings, report_path)
    else:
        _write_markdown_report(findings, report_path)

    console.print(f"Report written to [bold]{report_path}[/bold]")
    _print_summary(findings)
    if unreachable:
        click.echo(f"Could not reach server(s): {', '.join(unreachable)}", err=True)

    # Deliver findings to configured alert sinks
    delivery_failed = False
    if registry_config.alerts and findings:
        sinks = build_sinks(AlertConfig(alerts=registry_config.alerts), dry_run=dry_run_alerts)
        outcome = asyncio.run(emit_findings(findings, sinks))
        console.print(
            f"Alerts: {outcome.sent} sent, {outcome.deduped} deduped, {outcome.failed} failed."
        )
        delivery_failed = outcome.any_failed

    # Exit-code contract: could-not-run (2) > severity-gate (1) > success (0).
    if delivery_failed or unreachable:
        raise SystemExit(2)
    high_or_critical = [f for f in findings if f.severity in ("critical", "high")]
    if high_or_critical:
        raise SystemExit(1)

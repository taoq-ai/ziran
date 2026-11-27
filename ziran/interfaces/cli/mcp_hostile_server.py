"""CLI subcommand ``ziran mcp-hostile-server`` (spec 071).

Runs a hostile MCP server over stdio. Register it in an agent host's MCP config, ask
the host to call its ``lookup_glossary`` tool, then read the findings with
``ziran report``. stdout carries JSON-RPC only, so every message goes to stderr.
With ``--fault`` (spec 134) the tools named in ``--fault-tools`` return that fault.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console

from ziran.application.attacks.library import AttackLibrary
from ziran.application.mcp_server_surface.scoring import build_campaign_result
from ziran.domain.entities.mcp_server_surface import McpHostileRecord
from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from ziran.infrastructure.mcp_hostile.server import Fault

console = Console(stderr=True)

RECORD_FILE = "mcp_hostile_record.json"
FAMILIES = (
    "sampling-injection",
    "elicitation-phishing",
    "elicitation-overbroad",
    "roots-capability-creep",
)
FAULTS = ("error", "timeout", "oversize", "malformed", "slow")
_MAX_FAULT_TOOLS = 20
_TOOL_NAME = re.compile(r"[A-Za-z_][\w.-]{0,63}")


def _fault_tools(fault: str | None, names: str) -> list[str]:
    """The distinct tool names of ``--fault-tools``, checked against ``--fault``."""
    tools = list(dict.fromkeys(n.strip() for n in names.split(",") if n.strip()))
    if fault is None:
        if tools:
            raise click.UsageError("--fault-tools needs --fault")
        return []
    if not tools:
        raise click.UsageError("--fault needs --fault-tools")
    if len(tools) > _MAX_FAULT_TOOLS:
        raise click.BadParameter(f"at most {_MAX_FAULT_TOOLS} tools", param_hint="--fault-tools")
    bad = [t for t in tools if not _TOOL_NAME.fullmatch(t) or t == "lookup_glossary"]
    if bad:
        raise click.BadParameter(
            f"not a tool name to fault: {', '.join(bad)}", param_hint="--fault-tools"
        )
    return tools


@click.command("mcp-hostile-server")
@click.option(
    "--vector",
    "vector_ids",
    multiple=True,
    help="Server-surface vector ID to send (repeatable). Default: all of them.",
)
@click.option(
    "--family",
    "families",
    multiple=True,
    type=click.Choice(FAMILIES),
    help="Sub-family to send (repeatable). Adds to --vector.",
)
@click.option(
    "--record-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Folder for the record and the CampaignResult JSON.",
)
@click.option(
    "--timeout",
    type=click.FloatRange(min=1),
    default=120.0,
    show_default=True,
    help="Seconds to wait for each client reply (a person may answer a form).",
)
@click.option(
    "--fault",
    type=click.Choice(FAULTS),
    default=None,
    help="Fault the --fault-tools return: error, timeout (hangs 300s, then errors), oversize "
    "(1 MB), malformed (broken JSON) or slow (5s).",
)
@click.option(
    "--fault-tools",
    default="",
    help="Comma-separated tool names the server offers, each returning --fault (at most 20).",
)
def mcp_hostile_server(
    vector_ids: tuple[str, ...],
    families: tuple[str, ...],
    record_dir: Path,
    timeout: float,
    fault: Fault | None,
    fault_tools: str,
) -> None:
    """Act as a hostile MCP server over stdio and score the client's replies.

    \b
    Example MCP config entry:
        {"command": "ziran", "args": ["mcp-hostile-server", "--record-dir", "/abs/dir"]}
    """
    tools = _fault_tools(fault, fault_tools)
    surface = [v for v in AttackLibrary().vectors if v.mcp_server_request is not None]
    unknown = sorted(set(vector_ids) - {v.id for v in surface})
    if unknown:
        raise click.BadParameter(
            f"not a server-surface vector: {', '.join(unknown)}", param_hint="--vector"
        )
    pick_all = not vector_ids and not families
    selected = [
        v for v in surface if pick_all or v.id in vector_ids or any(f in v.tags for f in families)
    ]
    if not selected:
        raise click.UsageError("no server-surface vectors selected")
    try:
        from ziran.infrastructure.mcp_hostile.server import build_server
    except ImportError as exc:
        console.print("[red]The MCP SDK is not installed.[/red] Run: pip install 'ziran\\[mcp]'")
        raise SystemExit(1) from exc

    record_dir.mkdir(parents=True, exist_ok=True)
    campaign_id = f"mcp-hostile-{uuid.uuid4().hex[:12]}"
    reports = ReportGenerator(output_dir=record_dir)

    def write(record: McpHostileRecord) -> None:
        path = record_dir / RECORD_FILE
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record.model_dump(mode="json"), indent=2))
        os.replace(tmp, path)
        reports.save_json(build_campaign_result(selected, record, campaign_id=campaign_id))

    record = McpHostileRecord()
    write(record)  # a host that never calls the tool still leaves an all-unmeasured result
    console.print(
        f"[dim]mcp-hostile-server: {len(selected)} vector(s), record in {record_dir}[/dim]"
    )
    try:
        build_server(
            selected, record, on_update=write, timeout=timeout, fault=fault, fault_tools=tools
        ).run("stdio")
    finally:
        write(record)
        console.print(f"[dim]mcp-hostile-server: wrote {record_dir / RECORD_FILE}[/dim]")

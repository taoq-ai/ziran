"""CLI command for trace analysis.

Analyzes production traces (OTel or Langfuse) for dangerous tool
chains and generates reports.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.command("analyze-traces")
@click.option(
    "--source",
    type=click.Choice(["otel", "langfuse"], case_sensitive=False),
    required=True,
    help="Trace source format.",
)
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=False),
    default=None,
    help="Path to trace file (JSONL for OTel, JSON for Langfuse).",
)
@click.option(
    "--project-id",
    type=str,
    default=None,
    help="Langfuse project ID (API mode only).",
)
@click.option(
    "--since",
    type=str,
    default="24h",
    help="Time window for API fetch (e.g. '24h', '7d').",
)
@click.option(
    "--out",
    type=click.Path(),
    default="./reports/",
    help="Output directory for reports.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown", "html"], case_sensitive=False),
    default="json",
    help="Report format.",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def analyze_traces(
    source: str,
    input_path: str | None,
    project_id: str | None,
    since: str,
    out: str,
    output_format: str,
    verbose: bool,
) -> None:
    """Analyze production traces for dangerous tool chains.

    Ingests OTel or Langfuse traces and identifies dangerous tool
    chain patterns observed in production.
    """
    from ziran.application.trace_analysis.analyzer_service import (
        AnalyzerService,
    )

    if verbose:
        from ziran.infrastructure.logging.logger import setup_logging

        setup_logging(level="DEBUG")

    # Build ingestor
    ingestor = _build_ingestor(source)

    # Determine source path or API mode
    ingest_source: Path | str
    kwargs: dict[str, Any] = {}

    if input_path:
        ingest_source = Path(input_path)
    elif source == "langfuse":
        ingest_source = "api"
        if project_id:
            kwargs["project_id"] = project_id
        kwargs["since"] = since
    else:
        console.print("[red]Error:[/red] --input is required for OTel traces.")
        raise SystemExit(1)

    service = AnalyzerService(ingestor)

    console.print(
        Panel(
            f"Analyzing [bold]{source}[/bold] traces...",
            title="Trace Analysis",
        )
    )

    result = asyncio.run(service.analyze(ingest_source, **kwargs))

    # Display summary
    _display_summary(result)

    # Save report
    output_dir = Path(out)
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        report_path = output_dir / "trace_analysis.json"
        report_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2))
    elif output_format == "markdown":
        report_path = output_dir / "trace_analysis.md"
        report_path.write_text(_render_markdown(result))
    else:
        report_path = output_dir / "trace_analysis.json"
        report_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2))

    console.print(f"\n[dim]Report saved to {report_path}[/dim]")


def _build_ingestor(source: str) -> Any:
    """Create the appropriate ingestor."""
    if source == "otel":
        from ziran.infrastructure.trace_ingestors.otel_ingestor import (
            OTelIngestor,
        )

        return OTelIngestor()

    from ziran.infrastructure.trace_ingestors.langfuse_ingestor import (
        LangfuseIngestor,
    )

    return LangfuseIngestor()


def _display_summary(result: Any) -> None:
    """Print a Rich table summarizing the analysis results."""
    table = Table(title="Trace Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    table.add_row("Campaign ID", result.campaign_id)
    table.add_row("Source", result.source)
    table.add_row(
        "Sessions Analyzed",
        str(result.metadata.get("sessions_analyzed", 0)),
    )
    table.add_row(
        "Dangerous Chains",
        str(len(result.dangerous_tool_chains)),
    )
    table.add_row("Critical Chains", str(result.critical_chain_count))
    table.add_row("Total Vulnerabilities", str(result.total_vulnerabilities))

    console.print(table)

    if result.dangerous_tool_chains:
        chains_table = Table(title="Dangerous Tool Chains")
        chains_table.add_column("Tools", style="red")
        chains_table.add_column("Risk", style="yellow")
        chains_table.add_column("Type", style="cyan")
        chains_table.add_column("Score", style="bold")

        for chain_dict in result.dangerous_tool_chains:
            chains_table.add_row(
                " -> ".join(chain_dict.get("tools", [])),
                chain_dict.get("risk_level", ""),
                chain_dict.get("vulnerability_type", ""),
                f"{chain_dict.get('risk_score', 0):.3f}",
            )

        console.print(chains_table)


def _render_markdown(result: Any) -> str:
    """Render a simple Markdown report."""
    lines = [
        "# Trace Analysis Report",
        "",
        f"**Campaign ID:** {result.campaign_id}",
        f"**Source:** {result.source}",
        f"**Sessions Analyzed:** {result.metadata.get('sessions_analyzed', 0)}",
        f"**Total Vulnerabilities:** {result.total_vulnerabilities}",
        f"**Critical Chains:** {result.critical_chain_count}",
        "",
    ]

    if result.dangerous_tool_chains:
        lines.append("## Dangerous Tool Chains")
        lines.append("")
        lines.append("| Tools | Risk | Type | Score |")
        lines.append("|-------|------|------|-------|")
        for chain_dict in result.dangerous_tool_chains:
            tools = " -> ".join(chain_dict.get("tools", []))
            risk = chain_dict.get("risk_level", "")
            vtype = chain_dict.get("vulnerability_type", "")
            score = chain_dict.get("risk_score", 0)
            lines.append(f"| {tools} | {risk} | {vtype} | {score:.3f} |")

    lines.append("")
    return "\n".join(lines)

"""CLI main — Click commands with Rich output.

Entry point for the ``koan`` command-line tool. Provides commands
for scanning agents, discovering capabilities, and generating reports.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from koan import __version__
from koan.application.agent_scanner.scanner import AgentScanner
from koan.application.attacks.library import AttackLibrary
from koan.domain.entities.attack import OwaspLlmCategory
from koan.domain.entities.phase import CampaignResult, CoverageLevel, ScanPhase
from koan.infrastructure.logging.logger import setup_logging
from koan.infrastructure.storage.graph_storage import GraphStorage
from koan.interfaces.cli.reports import ReportGenerator

console = Console()

# ──────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────

BANNER = r"""
 _  _____   ___    _    _   _
| |/ / _ \ / _ \  | \  | | |
|   < | | / /_\ \ |  \ | | |
|   < | | |  _  | | . \| | |
|_|\_\___|_| | |_||_|\___|_|

AI Agent Security Testing Framework
"""


# ──────────────────────────────────────────────────────────────────────
# CLI Group
# ──────────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="koan")
@click.option(
    "--verbose", "-v", is_flag=True, default=False, help="Enable verbose (DEBUG) logging."
)
@click.option("--log-file", type=click.Path(), default=None, help="Write logs to file.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, log_file: str | None) -> None:
    """KOAN — AI Agent Security Testing Framework.

    Test AI agents for vulnerabilities using multi-phase scan campaigns
    and knowledge graph-based attack tracking.

    Get started:

        koan scan --framework langchain --agent-path ./my_agent.py

        koan discover ./my_agent.py

        koan library --list
    """
    ctx.ensure_object(dict)

    level = "DEBUG" if verbose else "INFO"
    setup_logging(level=level, log_file=log_file)


# ──────────────────────────────────────────────────────────────────────
# scan command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--framework",
    type=click.Choice(["langchain", "crewai", "bedrock"], case_sensitive=False),
    required=True,
    help="Agent framework to test.",
)
@click.option(
    "--agent-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to agent code/config file.",
)
@click.option(
    "--phases",
    multiple=True,
    type=click.Choice([p.value for p in ScanPhase], case_sensitive=False),
    help="Specific phases to run (default: all core phases).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="koan_results",
    help="Output directory for results.",
)
@click.option(
    "--custom-attacks",
    type=click.Path(exists=True),
    default=None,
    help="Directory with custom YAML attack vectors.",
)
@click.option(
    "--stop-on-critical / --no-stop-on-critical",
    default=True,
    help="Stop if a critical vulnerability is found.",
)
@click.option(
    "--coverage",
    type=click.Choice(["essential", "standard", "comprehensive"], case_sensitive=False),
    default="standard",
    help="Attack coverage level: essential (critical only), standard (critical+high), comprehensive (all).",
)
@click.option(
    "--concurrency",
    type=int,
    default=5,
    help="Maximum concurrent attacks per phase (default: 5).",
)
def scan(
    framework: str,
    agent_path: str,
    phases: tuple[str, ...],
    output: str,
    custom_attacks: str | None,
    stop_on_critical: bool,
    coverage: str,
    concurrency: int,
) -> None:
    """Run a security scan campaign against an AI agent.

    Executes a multi-phase security assessment that progressively
    discovers and tests for vulnerabilities.

    \b
    Examples:
        koan scan --framework langchain --agent-path ./my_agent.py
        koan scan --framework crewai --agent-path ./crew.py --phases reconnaissance trust_building
        koan scan --framework langchain --agent-path ./agent.py --custom-attacks ./my_attacks/
    """
    console.print(Panel(BANNER, style="bold green", expand=False))
    console.print()

    # Display configuration
    config_table = Table(title="Scan Configuration", show_header=False)
    config_table.add_column("Key", style="cyan")
    config_table.add_column("Value", style="white")
    config_table.add_row("Framework", framework)
    config_table.add_row("Agent Path", agent_path)
    config_table.add_row("Phases", ", ".join(phases) if phases else "all core phases")
    config_table.add_row("Output", output)
    config_table.add_row("Stop on Critical", str(stop_on_critical))
    config_table.add_row("Coverage", coverage)
    config_table.add_row("Concurrency", str(concurrency))
    if custom_attacks:
        config_table.add_row("Custom Attacks", custom_attacks)
    console.print(config_table)
    console.print()

    # Load adapter
    try:
        adapter = _load_agent_adapter(framework, agent_path)
    except Exception as e:
        console.print(f"[bold red]Error loading agent:[/bold red] {e}")
        sys.exit(1)

    # Build attack library
    custom_dirs = [Path(custom_attacks)] if custom_attacks else None
    attack_library = AttackLibrary(custom_dirs=custom_dirs)

    console.print(
        f"[dim]Loaded {attack_library.vector_count} attack vectors "
        f"across {len(attack_library.categories)} categories[/dim]"
    )
    console.print()

    # Parse phases
    phase_list: list[ScanPhase] | None = None
    if phases:
        phase_list = [ScanPhase(p) for p in phases]

    # Run campaign
    scanner = AgentScanner(adapter=adapter, attack_library=attack_library)
    coverage_level = CoverageLevel(coverage.lower())

    with console.status("[bold yellow]Running security scan campaign...[/bold yellow]"):
        result = asyncio.run(
            scanner.run_campaign(
                phases=phase_list,
                stop_on_critical=stop_on_critical,
                coverage=coverage_level,
                max_concurrent_attacks=concurrency,
            )
        )

    # Display results
    _display_results(result)

    # Save results
    output_dir = Path(output)
    _save_results(result, scanner.graph, output_dir)

    console.print(f"\n[dim]Results saved to {output_dir}/[/dim]")


# ──────────────────────────────────────────────────────────────────────
# discover command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--framework",
    type=click.Choice(["langchain", "crewai", "bedrock"], case_sensitive=False),
    required=True,
    help="Agent framework.",
)
@click.argument("agent_path", type=click.Path(exists=True))
def discover(framework: str, agent_path: str) -> None:
    """Discover capabilities of an agent without testing.

    Introspects the agent to find all available tools, skills,
    and permissions — without sending any attack prompts.

    \b
    Examples:
        koan discover --framework langchain ./my_agent.py
    """
    console.print(Panel(BANNER, style="bold cyan", expand=False))
    console.print()

    try:
        adapter = _load_agent_adapter(framework, agent_path)
    except Exception as e:
        console.print(f"[bold red]Error loading agent:[/bold red] {e}")
        sys.exit(1)

    with console.status("[bold yellow]Discovering capabilities...[/bold yellow]"):
        capabilities = asyncio.run(adapter.discover_capabilities())

    if not capabilities:
        console.print("[yellow]No capabilities discovered.[/yellow]")
        return

    table = Table(title=f"Agent Capabilities ({len(capabilities)} found)")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Type", style="magenta")
    table.add_column("Dangerous", style="red")
    table.add_column("Description", style="dim", max_width=50)

    for cap in capabilities:
        table.add_row(
            cap.id,
            cap.name,
            cap.type.value,
            "⚠️  YES" if cap.dangerous else "no",
            (cap.description or "")[:50],
        )

    console.print(table)


# ──────────────────────────────────────────────────────────────────────
# library command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.option("--list", "list_all", is_flag=True, help="List all attack vectors.")
@click.option(
    "--category",
    type=str,
    default=None,
    help="Filter by category.",
)
@click.option(
    "--phase",
    type=click.Choice([p.value for p in ScanPhase], case_sensitive=False),
    default=None,
    help="Filter by target phase.",
)
@click.option(
    "--custom-attacks",
    type=click.Path(exists=True),
    default=None,
    help="Include custom YAML attack vectors directory.",
)
@click.option(
    "--owasp",
    "owasp_filter",
    type=click.Choice([c.value for c in OwaspLlmCategory], case_sensitive=False),
    default=None,
    help="Filter vectors by OWASP LLM Top 10 category (e.g., LLM01).",
)
def library(
    list_all: bool,
    category: str | None,
    phase: str | None,
    custom_attacks: str | None,
    owasp_filter: str | None,
) -> None:
    """Browse the attack vector library.

    \b
    Examples:
        koan library --list
        koan library --category prompt_injection
        koan library --phase reconnaissance
        koan library --owasp LLM01
    """
    custom_dirs = [Path(custom_attacks)] if custom_attacks else None
    lib = AttackLibrary(custom_dirs=custom_dirs)

    vectors = lib.vectors

    if phase:
        vectors = [v for v in vectors if v.target_phase == ScanPhase(phase)]
    if category:
        vectors = [v for v in vectors if v.category.value == category]
    if owasp_filter:
        owasp_cat = OwaspLlmCategory(owasp_filter)
        vectors = [v for v in vectors if owasp_cat in v.owasp_mapping]

    if not vectors:
        console.print("[yellow]No matching attack vectors found.[/yellow]")
        return

    table = Table(title=f"Attack Library ({len(vectors)} vectors)")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Category", style="magenta")
    table.add_column("Phase", style="blue")
    table.add_column("Severity", style="red")
    table.add_column("OWASP", style="yellow")
    table.add_column("Prompts", style="green", justify="right")

    for v in vectors:
        severity_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(v.severity, "white")

        owasp_str = ", ".join(c.value for c in v.owasp_mapping) if v.owasp_mapping else "—"

        table.add_row(
            v.id,
            v.name,
            v.category.value,
            v.target_phase.value,
            f"[{severity_style}]{v.severity}[/{severity_style}]",
            owasp_str,
            str(v.prompt_count),
        )

    console.print(table)


# ──────────────────────────────────────────────────────────────────────
# report command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("result_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "json", "html", "terminal"]),
    default="terminal",
    help="Report output format.",
)
def report(result_file: str, fmt: str) -> None:
    """Regenerate a report from a saved campaign result.

    \b
    Examples:
        koan report ./koan_results/campaign_123_report.json
        koan report ./koan_results/campaign_123_report.json --format markdown
    """
    filepath = Path(result_file)

    try:
        with filepath.open() as f:
            data = json.load(f)
        result = CampaignResult.model_validate(data)
    except Exception as e:
        console.print(f"[bold red]Error loading result:[/bold red] {e}")
        sys.exit(1)

    if fmt == "terminal":
        _display_results(result)
    elif fmt == "markdown":
        generator = ReportGenerator(output_dir=filepath.parent)
        md_path = generator.save_markdown(result)
        console.print(f"[green]Markdown report saved to {md_path}[/green]")
    elif fmt == "html":
        generator = ReportGenerator(output_dir=filepath.parent)
        html_path = generator.save_html(result)
        console.print(f"[green]HTML report saved to {html_path}[/green]")
    elif fmt == "json":
        console.print_json(data=result.model_dump(mode="json"))


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _load_agent_adapter(framework: str, agent_path: str) -> Any:
    """Load an agent adapter for the specified framework.

    Dynamically imports the adapter module to keep framework
    dependencies optional (lazy loading).

    Args:
        framework: Framework name (langchain, crewai, bedrock).
        agent_path: Path to the agent code/config.

    Returns:
        Configured BaseAgentAdapter instance.

    Raises:
        click.ClickException: If the framework is not supported or import fails.
    """
    if framework == "langchain":
        try:
            from koan.infrastructure.adapters.langchain_adapter import LangChainAdapter
        except ImportError as e:
            raise click.ClickException(
                f"LangChain not installed. Run: uv sync --extra langchain\n{e}"
            ) from e

        # Load agent from path
        agent_executor = _load_python_object(agent_path, "agent_executor")
        return LangChainAdapter(agent_executor)

    elif framework == "crewai":
        try:
            from koan.infrastructure.adapters.crewai_adapter import CrewAIAdapter
        except ImportError as e:
            raise click.ClickException(
                f"CrewAI not installed. Run: uv sync --extra crewai\n{e}"
            ) from e

        crew = _load_python_object(agent_path, "crew")
        return CrewAIAdapter(crew)

    elif framework == "bedrock":
        raise click.ClickException(
            "Bedrock adapter is not yet implemented. "
            "Contributions welcome at https://github.com/taoq-ai/koan"
        )

    else:
        raise click.ClickException(f"Unsupported framework: {framework}")


def _load_python_object(filepath: str, object_name: str) -> Any:
    """Load a Python object from a file by executing it.

    Executes the file and extracts the named object from its namespace.

    Args:
        filepath: Path to the Python file.
        object_name: Name of the object to extract.

    Returns:
        The extracted Python object.

    Raises:
        click.ClickException: If the file can't be loaded or the object isn't found.
    """
    import importlib.util
    import sys

    path = Path(filepath).resolve()

    if not path.exists():
        raise click.ClickException(f"File not found: {filepath}")

    spec = importlib.util.spec_from_file_location("_koan_target", str(path))
    if spec is None or spec.loader is None:
        raise click.ClickException(f"Could not load module from: {filepath}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["_koan_target"] = module

    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise click.ClickException(f"Error executing {filepath}: {e}") from e

    obj = getattr(module, object_name, None)
    if obj is None:
        available = [a for a in dir(module) if not a.startswith("_")]
        raise click.ClickException(
            f"Object '{object_name}' not found in {filepath}. "
            f"Available objects: {', '.join(available)}"
        )

    return obj


def _display_results(result: CampaignResult) -> None:
    """Display campaign results in the terminal with Rich formatting.

    Args:
        result: The campaign result to display.
    """
    console.print()

    # Summary table
    summary_table = Table(title="🔍 Campaign Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Campaign ID", result.campaign_id)
    summary_table.add_row("Target Agent", result.target_agent)
    summary_table.add_row("Phases Executed", str(len(result.phases_executed)))
    summary_table.add_row(
        "Total Vulnerabilities",
        f"[bold red]{result.total_vulnerabilities}[/bold red]"
        if result.total_vulnerabilities > 0
        else "[green]0[/green]",
    )
    summary_table.add_row("Critical Attack Paths", str(len(result.critical_paths)))
    summary_table.add_row(
        "Dangerous Tool Chains",
        f"[bold red]{len(result.dangerous_tool_chains)}[/bold red]"
        if result.dangerous_tool_chains
        else "[green]0[/green]",
    )
    summary_table.add_row("Final Trust Score", f"{result.final_trust_score:.2f}")
    summary_table.add_row(
        "Result",
        "[bold red]⚠️  VULNERABLE[/bold red]"
        if result.success
        else "[bold green]✅ PASSED[/bold green]",
    )

    # Token usage (if tracked)
    tokens = result.token_usage
    if tokens.get("total_tokens", 0) > 0:
        summary_table.add_row("Prompt Tokens", f"{tokens['prompt_tokens']:,}")
        summary_table.add_row("Completion Tokens", f"{tokens['completion_tokens']:,}")
        summary_table.add_row("Total Tokens", f"[bold]{tokens['total_tokens']:,}[/bold]")
    if result.coverage_level:
        summary_table.add_row("Coverage Level", result.coverage_level)

    console.print(summary_table)

    # Phase details
    if result.phases_executed:
        console.print()
        phase_table = Table(title="📋 Phase Results")
        phase_table.add_column("Phase", style="blue")
        phase_table.add_column("Status", justify="center")
        phase_table.add_column("Vulnerabilities", justify="right")
        phase_table.add_column("Trust Score", justify="right")
        phase_table.add_column("Duration", justify="right")

        for pr in result.phases_executed:
            status = (
                "[red]⚠️  FINDINGS[/red]" if pr.vulnerabilities_found else "[green]✅ CLEAR[/green]"
            )
            phase_table.add_row(
                pr.phase.value.replace("_", " ").title(),
                status,
                str(len(pr.vulnerabilities_found)),
                f"{pr.trust_score:.2f}",
                f"{pr.duration_seconds:.1f}s",
            )

        console.print(phase_table)

    # Vulnerability details
    if result.total_vulnerabilities > 0:
        console.print()
        console.print("[bold red]🚨 Vulnerabilities Found:[/bold red]")
        console.print()

        for pr in result.phases_executed:
            if pr.vulnerabilities_found:
                console.print(f"  [bold]{pr.phase.value.replace('_', ' ').title()}:[/bold]")
                for vuln_id in pr.vulnerabilities_found:
                    artifact = pr.artifacts.get(vuln_id, {})
                    name = artifact.get("name", vuln_id)
                    severity = artifact.get("severity", "unknown")
                    console.print(f"    • [red]{name}[/red] ({severity}) — `{vuln_id}`")
                console.print()

    # Attack paths
    if result.critical_paths:
        console.print("[bold red]🔗 Critical Attack Paths:[/bold red]")
        console.print()
        for i, path in enumerate(result.critical_paths[:5], 1):
            console.print(f"  {i}. {' → '.join(path)}")
        if len(result.critical_paths) > 5:
            console.print(f"\n  [dim]...and {len(result.critical_paths) - 5} more paths[/dim]")
        console.print()

    # Dangerous tool chains
    if result.dangerous_tool_chains:
        console.print("[bold red]⛓️  Dangerous Tool Chains:[/bold red]")
        console.print()

        chain_table = Table(show_header=True, header_style="bold")
        chain_table.add_column("Risk", style="bold", width=10)
        chain_table.add_column("Type", style="magenta")
        chain_table.add_column("Tools", style="cyan")
        chain_table.add_column("Description", style="dim", max_width=50)

        for chain in result.dangerous_tool_chains[:10]:
            risk = chain.get("risk_level", "unknown")
            risk_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
            }.get(risk, "white")
            chain_table.add_row(
                f"[{risk_style}]{risk}[/{risk_style}]",
                chain.get("vulnerability_type", ""),
                " → ".join(chain.get("tools", [])),
                chain.get("exploit_description", "")[:50],
            )

        console.print(chain_table)
        if len(result.dangerous_tool_chains) > 10:
            console.print(
                f"\n  [dim]...and {len(result.dangerous_tool_chains) - 10} more chains[/dim]"
            )
        console.print()


def _save_results(
    result: CampaignResult,
    graph: Any,
    output_dir: Path,
) -> None:
    """Save campaign results and graph to disk.

    Args:
        result: Campaign result to save.
        graph: AttackKnowledgeGraph to persist.
        output_dir: Directory for output files.
    """
    from koan.application.knowledge_graph.graph import AttackKnowledgeGraph

    report_gen = ReportGenerator(output_dir=output_dir)

    # Save JSON report
    json_path = report_gen.save_json(result)
    console.print(f"  [dim]JSON report: {json_path}[/dim]")

    # Save Markdown report
    md_path = report_gen.save_markdown(result)
    console.print(f"  [dim]Markdown report: {md_path}[/dim]")

    # Save interactive HTML report
    if isinstance(graph, AttackKnowledgeGraph):
        html_path = report_gen.save_html(result, graph_state=graph.export_state())
    else:
        html_path = report_gen.save_html(result)
    console.print(f"  [dim]HTML report: {html_path}[/dim]")

    # Save graph state
    if isinstance(graph, AttackKnowledgeGraph):
        storage = GraphStorage(output_dir=output_dir)
        graph_path = storage.save(graph, result.campaign_id)
        console.print(f"  [dim]Graph state: {graph_path}[/dim]")


if __name__ == "__main__":
    cli()

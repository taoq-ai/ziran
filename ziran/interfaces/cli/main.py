"""CLI main — Click commands with Rich output.

Entry point for the ``ziran`` command-line tool. Provides commands
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

from ziran import __version__
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.application.factories import build_strategy, load_agent_adapter, load_remote_adapter
from ziran.domain.entities.attack import OwaspLlmCategory
from ziran.domain.entities.phase import CampaignResult, CoverageLevel, ScanPhase
from ziran.infrastructure.logging.logger import setup_logging
from ziran.infrastructure.storage.graph_storage import GraphStorage
from ziran.interfaces.cli.reports import ReportGenerator

console = Console()

# ──────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────

BANNER = r"""
 _______ _____ _____            _   _
|___  / |  __ \_   _|     /\   | \ | |
   / /  | |__) || |      /  \  |  \| |
  / /   |  _  / | |     / /\ \ | . ` |
 / /__  | | \ \_| |_   / ____ \| |\  |
/_____| |_|  \_\_____| /_/    \_\_| \_|

AI Agent Security Testing Framework
"""


# ──────────────────────────────────────────────────────────────────────
# CLI Group
# ──────────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="ziran")
@click.option(
    "--verbose", "-v", is_flag=True, default=False, help="Enable verbose (DEBUG) logging."
)
@click.option("--log-file", type=click.Path(), default=None, help="Write logs to file.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, log_file: str | None) -> None:
    """ZIRAN — AI Agent Security Testing Framework.

    Test AI agents for vulnerabilities using multi-phase scan campaigns
    and knowledge graph-based attack tracking.

    Get started:

        ziran scan --framework langchain --agent-path ./my_agent.py

        ziran discover ./my_agent.py

        ziran library --list
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
    type=click.Choice(["langchain", "crewai", "bedrock", "agentcore"], case_sensitive=False),
    default=None,
    help="Agent framework to test (for in-process scanning).",
)
@click.option(
    "--agent-path",
    type=click.Path(exists=True),
    default=None,
    help="Path to agent code/config file (for in-process scanning).",
)
@click.option(
    "--target",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML target config for remote agent scanning.",
)
@click.option(
    "--protocol",
    type=click.Choice(["rest", "openai", "mcp", "a2a", "browser", "auto"], case_sensitive=False),
    default=None,
    help="Override protocol type (used with --target).",
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
    default="ziran_results",
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
@click.option(
    "--llm-provider",
    type=str,
    default=None,
    envvar="ZIRAN_LLM_PROVIDER",
    help="LLM provider for AI-powered features (e.g. 'openai', 'anthropic', 'bedrock'). "
    "Uses LiteLLM routing. Env: ZIRAN_LLM_PROVIDER.",
)
@click.option(
    "--llm-model",
    type=str,
    default=None,
    envvar="ZIRAN_LLM_MODEL",
    help="LLM model name for AI-powered features (e.g. 'gpt-4o', 'claude-sonnet-4-20250514'). "
    "Env: ZIRAN_LLM_MODEL.",
)
@click.option(
    "--attack-timeout",
    type=float,
    default=60.0,
    help="Per-attack timeout in seconds (default: 60).",
)
@click.option(
    "--phase-timeout",
    type=float,
    default=300.0,
    help="Per-phase timeout in seconds (default: 300).",
)
@click.option(
    "--strategy",
    type=click.Choice(["fixed", "adaptive", "llm-adaptive"], case_sensitive=False),
    default="fixed",
    help="Campaign execution strategy: 'fixed' (sequential phases), "
    "'adaptive' (rule-based adaptation), or 'llm-adaptive' (LLM-driven). "
    "Default: fixed.",
)
@click.option(
    "--streaming / --no-streaming",
    default=False,
    help="Use streaming invocation for attacks (real-time response monitoring).",
)
@click.option(
    "--encoding",
    type=click.Choice(
        [
            "base64",
            "rot13",
            "leetspeak",
            "homoglyph",
            "hex",
            "whitespace",
            "mixed_case",
            "payload_split",
            "pig_latin",
            "reverse",
            "word_shuffle",
            "token_boundary",
        ],
        case_sensitive=False,
    ),
    multiple=True,
    default=(),
    help="Prompt encoding/obfuscation to apply. Can be specified multiple times. "
    "Each encoding generates additional attack variants alongside the originals.",
)
@click.option(
    "--quality-scoring",
    is_flag=True,
    default=False,
    help="Enable StrongREJECT-style quality-aware jailbreak scoring. "
    "Measures response specificity and convincingness (requires --llm-provider).",
)
@click.option(
    "--utility-tasks",
    type=click.Path(exists=True),
    default=None,
    help="YAML file with legitimate tasks for utility-under-attack measurement. "
    "Runs tasks before and after the campaign to measure utility degradation.",
)
@click.option(
    "--otel",
    is_flag=True,
    default=False,
    help="Enable OpenTelemetry tracing (requires opentelemetry-sdk). "
    "Exports spans to the console by default.",
)
@click.option(
    "--resume",
    is_flag=True,
    default=False,
    help="Resume a previously interrupted campaign from the last checkpoint. "
    "Reads checkpoint from the --output directory.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate configuration and show attack plan without executing. "
    "Loads the adapter, discovers capabilities, and counts attack vectors.",
)
def scan(
    framework: str | None,
    agent_path: str | None,
    target: str | None,
    protocol: str | None,
    phases: tuple[str, ...],
    output: str,
    custom_attacks: str | None,
    stop_on_critical: bool,
    coverage: str,
    concurrency: int,
    llm_provider: str | None,
    llm_model: str | None,
    attack_timeout: float,
    phase_timeout: float,
    strategy: str,
    streaming: bool,
    encoding: tuple[str, ...],
    quality_scoring: bool,
    utility_tasks: str | None,
    otel: bool,
    resume: bool,
    dry_run: bool,
) -> None:
    """Run a security scan campaign against an AI agent.

    Executes a multi-phase security assessment that progressively
    discovers and tests for vulnerabilities.

    Use --framework + --agent-path for in-process scanning, or
    --target for remote agent scanning over HTTPS.

    \b
    Examples:
        ziran scan --framework langchain --agent-path ./my_agent.py
        ziran scan --target ./target.yaml
        ziran scan --target ./target.yaml --protocol a2a
        ziran scan --framework crewai --agent-path ./crew.py --phases reconnaissance trust_building
    """
    # Enable OpenTelemetry if requested
    if otel:
        from ziran.infrastructure.telemetry.tracing import configure_console_exporter

        configure_console_exporter()
        console.print("[dim]OpenTelemetry tracing enabled (console exporter)[/dim]")

    # Validate mutually exclusive options
    has_local = framework is not None or agent_path is not None
    has_remote = target is not None

    if has_local and has_remote:
        console.print(
            "[bold red]Error:[/bold red] --framework/--agent-path and --target "
            "are mutually exclusive. Use one or the other."
        )
        sys.exit(1)

    if not has_local and not has_remote:
        console.print(
            "[bold red]Error:[/bold red] Provide either --framework + --agent-path "
            "(in-process) or --target (remote) to specify the agent."
        )
        sys.exit(1)

    if has_local and (framework is None or agent_path is None):
        console.print(
            "[bold red]Error:[/bold red] Both --framework and --agent-path "
            "are required for in-process scanning."
        )
        sys.exit(1)

    console.print(Panel(BANNER, style="bold green", expand=False))
    console.print()

    # Display configuration
    config_table = Table(title="Scan Configuration", show_header=False)
    config_table.add_column("Key", style="cyan")
    config_table.add_column("Value", style="white")
    if has_remote:
        mode_label = "Browser (Headless)" if protocol == "browser" else "Remote (HTTPS)"
        config_table.add_row("Mode", mode_label)
        config_table.add_row("Target Config", str(target))
        if protocol:
            config_table.add_row("Protocol Override", protocol)
    else:
        config_table.add_row("Mode", "In-Process")
        config_table.add_row("Framework", str(framework))
        config_table.add_row("Agent Path", str(agent_path))
    config_table.add_row("Phases", ", ".join(phases) if phases else "all core phases")
    config_table.add_row("Output", output)
    config_table.add_row("Stop on Critical", str(stop_on_critical))
    config_table.add_row("Coverage", coverage)
    config_table.add_row("Concurrency", str(concurrency))
    if strategy != "fixed":
        config_table.add_row("Strategy", strategy)
    if streaming:
        config_table.add_row("Streaming", "enabled")
    if custom_attacks:
        config_table.add_row("Custom Attacks", custom_attacks)
    if llm_provider or llm_model:
        config_table.add_row("LLM Provider", llm_provider or "litellm")
        config_table.add_row("LLM Model", llm_model or "gpt-4o")
    if quality_scoring:
        config_table.add_row("Quality Scoring", "enabled (StrongREJECT-style)")
    if dry_run:
        config_table.add_row("Dry Run", "enabled (no attacks will execute)")
    console.print(config_table)
    console.print()

    # ── Config validation warnings ──────────────────────────────────
    _warn_config_issues(
        attack_timeout=attack_timeout,
        phase_timeout=phase_timeout,
        concurrency=concurrency,
        strategy=strategy,
        llm_provider=llm_provider,
        encoding=encoding,
    )

    # Load adapter
    try:
        if has_remote:
            adapter, config = load_remote_adapter(str(target), protocol)
            console.print(f"[dim]Target: {config.url}[/dim]")
            console.print(f"[dim]Protocol: {config.protocol.value}[/dim]")
            if config.auth:
                console.print(f"[dim]Auth: {config.auth.type.value}[/dim]")
            console.print()
        else:
            adapter = load_agent_adapter(str(framework), str(agent_path))
    except (ValueError, ImportError, FileNotFoundError, Exception) as e:
        console.print(f"[bold red]Error loading agent:[/bold red] {e}")
        sys.exit(1)

    # Build attack library
    custom_dirs = [Path(custom_attacks)] if custom_attacks else None
    attack_library = AttackLibrary(custom_dirs=custom_dirs)

    console.print(
        f"[dim]Loaded {attack_library.vector_count} attack vectors "
        f"across {len(attack_library.categories)} categories[/dim]"
    )
    if attack_library.load_error_count > 0:
        console.print(
            f"[yellow]\u26a0 {attack_library.load_error_count} vectors failed to "
            f"parse \u2014 use --verbose to see errors[/yellow]"
        )
    console.print()

    # ── Dry-run: show plan and exit without executing ───────────────
    if dry_run:
        _dry_run_summary(
            adapter=adapter,
            attack_library=attack_library,
            coverage=coverage,
            phases=phases,
            has_remote=has_remote,
            target=target,
            protocol=protocol,
        )
        return

    # Parse phases
    phase_list: list[ScanPhase] | None = None
    if phases:
        phase_list = [ScanPhase(p) for p in phases]

    # Run campaign
    scanner_config: dict[str, Any] = {
        "attack_timeout": attack_timeout,
        "phase_timeout": phase_timeout,
        "quality_scoring": quality_scoring,
    }

    # Initialize LLM client if provider/model specified
    llm_client = None
    if llm_provider or llm_model:
        try:
            from ziran.infrastructure.llm import create_llm_client

            llm_client = create_llm_client(
                provider=llm_provider or "litellm",
                model=llm_model or "gpt-4o",
            )
            scanner_config["llm_client"] = llm_client
            console.print("[dim]LLM backbone enabled for AI-powered features[/dim]")
        except ImportError:
            console.print(
                "[yellow]Warning:[/yellow] litellm not installed. "
                "LLM-powered features disabled. Run: uv sync --extra llm"
            )
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Failed to initialize LLM client: {e}")

    scanner = AgentScanner(adapter=adapter, attack_library=attack_library, config=scanner_config)
    coverage_level = CoverageLevel(coverage.lower())

    # Build campaign strategy
    campaign_strategy = build_strategy(strategy, stop_on_critical, llm_client)
    if strategy != "fixed":
        console.print(f"[dim]Campaign strategy: {strategy}[/dim]")

    # Load utility tasks if specified
    loaded_utility_tasks = None
    if utility_tasks:
        from ziran.application.utility.measurer import load_utility_tasks

        loaded_utility_tasks = load_utility_tasks(Path(utility_tasks))
        console.print(f"[dim]Utility tasks: {len(loaded_utility_tasks)} tasks loaded[/dim]")

    # Set up checkpoint manager (always enabled — used for resume and safety)
    from ziran.application.agent_scanner.checkpoint import CheckpointManager

    output_dir = Path(output)
    checkpoint_mgr = CheckpointManager(output_dir)

    if resume:
        if checkpoint_mgr.exists():
            console.print(f"[cyan]Resuming from checkpoint:[/cyan] {checkpoint_mgr.path}")
        else:
            console.print(
                "[yellow]Warning:[/yellow] --resume specified but no checkpoint found "
                f"in {output_dir}. Starting fresh."
            )

    with console.status("[bold yellow]Running security scan campaign...[/bold yellow]"):
        result = asyncio.run(
            scanner.run_campaign(
                phases=phase_list,
                stop_on_critical=stop_on_critical,
                coverage=coverage_level,
                max_concurrent_attacks=concurrency,
                strategy=campaign_strategy,
                streaming=streaming,
                encoding=list(encoding) if encoding else None,
                utility_tasks=loaded_utility_tasks,
                checkpoint_manager=checkpoint_mgr,
                resume_from_checkpoint=resume,
            )
        )

    # Display results
    _display_results(result)

    # Save results
    _save_results(result, scanner.graph, output_dir)

    console.print(f"\n[dim]Results saved to {output_dir}/[/dim]")


# ──────────────────────────────────────────────────────────────────────
# discover command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--framework",
    type=click.Choice(["langchain", "crewai", "bedrock", "agentcore"], case_sensitive=False),
    default=None,
    help="Agent framework (for in-process discovery).",
)
@click.option(
    "--target",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML target config for remote agent discovery.",
)
@click.option(
    "--protocol",
    type=click.Choice(["rest", "openai", "mcp", "a2a", "browser", "auto"], case_sensitive=False),
    default=None,
    help="Override protocol type (used with --target).",
)
@click.argument("agent_path", type=click.Path(exists=True), required=False, default=None)
def discover(
    framework: str | None,
    target: str | None,
    protocol: str | None,
    agent_path: str | None,
) -> None:
    """Discover capabilities of an agent without testing.

    Introspects the agent to find all available tools, skills,
    and permissions — without sending any attack prompts.

    Use --framework + AGENT_PATH for local agents, or --target for remote.

    \b
    Examples:
        ziran discover --framework langchain ./my_agent.py
        ziran discover --target ./target.yaml
    """
    console.print(Panel(BANNER, style="bold cyan", expand=False))
    console.print()

    has_local = framework is not None or agent_path is not None
    has_remote = target is not None

    if has_local and has_remote:
        console.print(
            "[bold red]Error:[/bold red] --framework/AGENT_PATH and --target "
            "are mutually exclusive."
        )
        sys.exit(1)

    if not has_local and not has_remote:
        console.print(
            "[bold red]Error:[/bold red] Provide either --framework + AGENT_PATH or --target."
        )
        sys.exit(1)

    try:
        if has_remote:
            adapter, _config = load_remote_adapter(str(target), protocol)
        else:
            if framework is None or agent_path is None:
                console.print(
                    "[bold red]Error:[/bold red] Both --framework and AGENT_PATH "
                    "are required for in-process discovery."
                )
                sys.exit(1)
            adapter = load_agent_adapter(framework, agent_path)
    except (ValueError, ImportError, FileNotFoundError, Exception) as e:
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
        ziran library --list
        ziran library --category prompt_injection
        ziran library --phase reconnaissance
        ziran library --owasp LLM01
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
        ziran report ./ziran_results/campaign_123_report.json
        ziran report ./ziran_results/campaign_123_report.json --format markdown
    """
    filepath = Path(result_file)

    try:
        with filepath.open() as f:
            data = json.load(f)
        result = CampaignResult.model_validate(data)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[bold red]Error loading result:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error loading result:[/bold red] {e}")
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
# poc command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("result_file", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output directory for PoC files (default: same dir as result + /pocs).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["python", "curl", "markdown", "all"], case_sensitive=False),
    default="all",
    help="PoC output format.",
)
def poc(result_file: str, output: str | None, fmt: str) -> None:
    """Generate proof-of-concept exploit scripts from scan results.

    Creates reproducible PoC artifacts for all confirmed vulnerabilities
    in a campaign result file.

    \b
    Examples:
        ziran poc ./ziran_results/campaign_123_report.json
        ziran poc ./ziran_results/campaign_123_report.json --format python
        ziran poc ./ziran_results/campaign_123_report.json -o ./my_pocs/
    """
    from ziran.application.poc.generator import PoCGenerator

    filepath = Path(result_file)

    try:
        with filepath.open() as f:
            data = json.load(f)
        result = CampaignResult.model_validate(data)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[bold red]Error loading result:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error loading result:[/bold red] {e}")
        sys.exit(1)

    from ziran.domain.entities.attack import AttackResult as _AttackResult

    successful: list[_AttackResult] = []
    for raw in result.attack_results:
        ar = _AttackResult.model_validate(raw) if isinstance(raw, dict) else raw
        if ar.successful:
            successful.append(ar)

    if not successful:
        console.print("[yellow]No successful attacks found — no PoCs to generate.[/yellow]")
        return

    poc_dir = Path(output) if output else filepath.parent / "pocs"
    generator = PoCGenerator(output_dir=poc_dir)

    generated: list[Path] = []
    if fmt in ("python", "all"):
        for r in successful:
            path = generator.generate_python_poc(r, result.campaign_id)
            generated.append(path)
    if fmt in ("curl", "all"):
        for r in successful:
            path = generator.generate_curl_poc(r, campaign_id=result.campaign_id)
            generated.append(path)
    if fmt in ("markdown", "all"):
        path = generator.generate_markdown_guide(successful, result.campaign_id)
        generated.append(path)

    console.print(f"[green]Generated {len(generated)} PoC artifact(s) in {poc_dir}/[/green]")
    for p in generated:
        console.print(f"  [dim]{p.name}[/dim]")


# ──────────────────────────────────────────────────────────────────────
# policy command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("result_file", type=click.Path(exists=True))
@click.option(
    "--policy",
    "-p",
    "policy_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to a YAML policy file (default: built-in ZIRAN policy).",
)
def policy(result_file: str, policy_path: str | None) -> None:
    """Evaluate campaign results against an organisational security policy.

    Checks a scan result JSON file against a set of policy rules and
    reports violations, warnings, and an overall pass/fail status.

    \b
    Examples:
        ziran policy ./ziran_results/campaign_123_report.json
        ziran policy ./ziran_results/campaign_123_report.json --policy my_policy.yaml
    """
    from ziran.application.policy.engine import PolicyEngine

    filepath = Path(result_file)

    try:
        with filepath.open() as f:
            data = json.load(f)
        result = CampaignResult.model_validate(data)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[bold red]Error loading result:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error loading result:[/bold red] {e}")
        sys.exit(1)

    try:
        if policy_path:
            engine = PolicyEngine.from_yaml(Path(policy_path))
        else:
            engine = PolicyEngine.default()
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error loading policy:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error loading policy:[/bold red] {e}")
        sys.exit(1)

    verdict = engine.evaluate(result)
    _display_policy_verdict(verdict)


def _display_policy_verdict(verdict: Any) -> None:
    """Render a PolicyVerdict to the console."""
    from ziran.domain.entities.policy import PolicyVerdict

    assert isinstance(verdict, PolicyVerdict)

    status_style = "bold green" if verdict.passed else "bold red"
    status_text = "PASSED" if verdict.passed else "FAILED"

    console.print()
    console.print(
        Panel(
            f"[{status_style}]{status_text}[/{status_style}]  {verdict.policy_name}",
            title="Policy Evaluation",
            expand=False,
        )
    )
    console.print()

    if verdict.violations:
        err_table = Table(
            title="[red]Errors (blocking)[/red]",
            show_lines=True,
        )
        err_table.add_column("Rule", style="red")
        err_table.add_column("Message", style="white")
        for v in verdict.violations:
            err_table.add_row(v.rule_type.value, v.message)
        console.print(err_table)
        console.print()

    if verdict.warnings:
        warn_table = Table(
            title="[yellow]Warnings[/yellow]",
            show_lines=True,
        )
        warn_table.add_column("Rule", style="yellow")
        warn_table.add_column("Message", style="white")
        for w in verdict.warnings:
            warn_table.add_row(w.rule_type.value, w.message)
        console.print(warn_table)
        console.print()

    if verdict.info:
        info_table = Table(
            title="[blue]Informational[/blue]",
            show_lines=True,
        )
        info_table.add_column("Rule", style="blue")
        info_table.add_column("Message", style="dim")
        for i in verdict.info:
            info_table.add_row(i.rule_type.value, i.message)
        console.print(info_table)
        console.print()

    console.print(f"[dim]{verdict.summary}[/dim]")

    if not verdict.passed:
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# audit command (static analysis)
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Only show findings at this severity or above.",
)
def audit(path: str, severity: str | None) -> None:
    """Static security analysis of agent source code.

    Scans Python files for common agent security anti-patterns such as
    hard-coded secrets, dangerous tool permissions, SQL injection risks,
    and PII exposure — all without executing the agent.

    PATH can be a single file or a directory (recursive scan).

    \b
    Examples:
        ziran audit ./my_agent.py
        ziran audit ./agents/ --severity high
    """
    from ziran.application.static_analysis.analyzer import (
        AnalysisReport,
        StaticAnalyzer,
    )

    target = Path(path)
    analyzer = StaticAnalyzer()

    if target.is_file():
        findings = analyzer.analyze_file(target)
        report = AnalysisReport(files_analyzed=1, findings=findings)
    else:
        report = analyzer.analyze_directory(target)

    # Filter by severity if requested
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if severity:
        min_level = severity_order[severity]
        report.findings = [f for f in report.findings if severity_order[f.severity] <= min_level]

    _display_audit_report(report)


def _display_audit_report(report: Any) -> None:
    """Render an AnalysisReport to the console."""
    console.print()

    if not report.findings:
        console.print(
            Panel(
                "[bold green]No issues found[/bold green]",
                title="Static Analysis",
                expand=False,
            )
        )
        console.print(f"[dim]Files analysed: {report.files_analyzed}[/dim]")
        return

    # Summary
    console.print(
        Panel(
            f"[bold]Found {report.total_issues} issue(s) "
            f"in {report.files_analyzed} file(s)[/bold]\n"
            f"  [red]Critical: {report.critical_count}[/red]  "
            f"[yellow]High: {report.high_count}[/yellow]",
            title="Static Analysis",
            expand=False,
        )
    )
    console.print()

    severity_styles = {
        "critical": "bold red",
        "high": "yellow",
        "medium": "cyan",
        "low": "dim",
    }

    findings_table = Table(show_lines=True)
    findings_table.add_column("Check", style="cyan", width=6)
    findings_table.add_column("Severity", width=10)
    findings_table.add_column("Message")
    findings_table.add_column("Location", style="dim")

    for f in report.findings:
        sev_style = severity_styles.get(f.severity, "white")
        loc = f.file_path
        if f.line_number:
            loc += f":{f.line_number}"
        findings_table.add_row(
            f.check_id,
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.message,
            loc,
        )

    console.print(findings_table)

    # Recommendations
    recs = {f.check_id: f.recommendation for f in report.findings if f.recommendation}
    if recs:
        console.print()
        console.print("[bold]Recommendations:[/bold]")
        for check_id, rec in sorted(recs.items()):
            console.print(f"  [cyan]{check_id}[/cyan]: {rec}")

    if not report.passed:
        console.print()
        console.print("[bold red]FAILED — critical issues found[/bold red]")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# validate command (config validation)
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("target_config", type=click.Path(exists=True))
@click.option(
    "--protocol",
    type=click.Choice(["rest", "openai", "mcp", "a2a", "browser", "auto"], case_sensitive=False),
    default=None,
    help="Override protocol type.",
)
def validate(target_config: str, protocol: str | None) -> None:
    """Validate a target YAML configuration file.

    Checks that the configuration file is well-formed, the target URL
    is reachable, auth tokens resolve, and the protocol can be detected.

    \b
    Examples:
        ziran validate ./target.yaml
        ziran validate ./target.yaml --protocol openai
    """
    from ziran.domain.entities.target import TargetConfig, TargetConfigError, load_target_config

    config_path = Path(target_config)
    checks: list[tuple[str, bool, str]] = []  # (label, passed, detail)

    # 1. Load and validate config (YAML parse + schema validation)
    config: TargetConfig | None = None
    try:
        config = load_target_config(config_path)
        checks.append(("YAML parse", True, "Configuration file is valid YAML"))
        checks.append(("Config schema", True, f"URL: {config.url}"))
    except TargetConfigError as e:
        msg = str(e)
        if "YAML" in msg or "parse" in msg.lower():
            checks.append(("YAML parse", False, msg))
        else:
            checks.append(("YAML parse", True, "Configuration file is valid YAML"))
            checks.append(("Config schema", False, msg))
        _display_validation_results(checks)
        return
    except Exception as e:
        checks.append(("Config load", False, str(e)))
        _display_validation_results(checks)
        return

    # 2. Check protocol
    effective_protocol = protocol or config.protocol.value
    checks.append(("Protocol", True, effective_protocol))

    # 3. Check auth token resolution
    if config.auth:
        env_var = config.auth.env_var
        if env_var:
            import os

            resolved = os.environ.get(env_var)
            if resolved:
                checks.append(("Auth token", True, f"Resolved from env ${env_var}"))
            else:
                checks.append(("Auth token", False, f"Env var ${env_var} not set"))
        elif config.auth.token:
            checks.append(("Auth token", True, f"Type: {config.auth.type.value}"))
        else:
            checks.append(("Auth token", False, "Auth configured but no token provided"))
    else:
        checks.append(("Auth", True, "No auth configured (anonymous)"))

    # 4. Check URL reachability (best-effort)
    try:
        import urllib.request

        req = urllib.request.Request(str(config.url), method="HEAD")
        urllib.request.urlopen(req, timeout=5)
        checks.append(("URL reachable", True, str(config.url)))
    except Exception as e:
        checks.append(("URL reachable", False, f"{e}"))

    _display_validation_results(checks)


def _display_validation_results(checks: list[tuple[str, bool, str]]) -> None:
    """Render validation check results."""
    console.print()
    all_passed = all(passed for _, passed, _ in checks)

    for label, passed, detail in checks:
        icon = "[green]✓[/green]" if passed else "[red]✗[/red]"
        console.print(f"  {icon} {label}: {detail}")

    console.print()
    if all_passed:
        console.print("[green]✓ All checks passed — configuration is valid.[/green]")
    else:
        console.print("[red]✗ Some checks failed — review the errors above.[/red]")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# ci command (CI/CD quality gate)
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("result_file", type=click.Path(exists=True))
@click.option(
    "--gate-config",
    "-g",
    "gate_config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to a quality-gate YAML config (default: built-in thresholds).",
)
@click.option(
    "--policy",
    "-p",
    "policy_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to a YAML policy file for additional evaluation.",
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(),
    default=None,
    help="Write a SARIF v2.1.0 report to this path.",
)
@click.option(
    "--github-annotations/--no-github-annotations",
    default=True,
    help="Emit GitHub Actions annotations (default: on).",
)
@click.option(
    "--github-summary/--no-github-summary",
    default=True,
    help="Write a GitHub Actions step summary (default: on).",
)
def ci(
    result_file: str,
    gate_config_path: str | None,
    policy_path: str | None,
    sarif_path: str | None,
    *,
    github_annotations: bool,
    github_summary: bool,
) -> None:
    """Evaluate campaign results for CI/CD quality gating.

    Runs quality-gate checks against a scan result JSON file
    and emits outputs suitable for CI/CD environments:

    \b
      - GitHub Actions annotations (::error / ::warning)
      - SARIF v2.1.0 report for GitHub Code Scanning
      - Step summary in Markdown
      - Non-zero exit code on failure

    \b
    Examples:
        ziran ci ./ziran_results/campaign_123_report.json
        ziran ci results.json --gate-config gate.yaml --sarif results.sarif
        ziran ci results.json --no-github-annotations --sarif results.sarif
    """
    from ziran.application.cicd.gate import QualityGate
    from ziran.application.cicd.github_actions import (
        emit_annotations,
        set_output,
        write_step_summary,
    )
    from ziran.application.cicd.sarif import write_sarif

    filepath = Path(result_file)

    # 1. Load campaign result
    try:
        with filepath.open() as f:
            data = json.load(f)
        result = CampaignResult.model_validate(data)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[bold red]Error loading result:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error loading result:[/bold red] {e}")
        sys.exit(1)

    # 2. Build quality gate
    try:
        gate = QualityGate.from_yaml(Path(gate_config_path)) if gate_config_path else QualityGate()
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error loading gate config:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error loading gate config:[/bold red] {e}")
        sys.exit(1)

    # 3. Evaluate
    gate_result = gate.evaluate(result)

    # 4. Console output (always shown)
    _display_gate_result(gate_result)

    # 5. SARIF output
    if sarif_path:
        try:
            written = write_sarif(result, Path(sarif_path))
            console.print(f"[dim]SARIF report: {written}[/dim]")
        except Exception as e:
            console.print(f"[yellow]Warning: SARIF generation failed: {e}[/yellow]")

    # 6. GitHub annotations
    if github_annotations:
        annotations = emit_annotations(result)
        for ann in annotations:
            print(ann)

    # 7. GitHub step summary
    if github_summary:
        write_step_summary(gate_result, result)

    # 8. GitHub outputs
    set_output("status", gate_result.status.value)
    set_output("trust_score", f"{gate_result.trust_score:.2f}")
    set_output("total_findings", str(gate_result.finding_counts.total))
    set_output("critical_findings", str(gate_result.finding_counts.critical))

    # 9. Policy evaluation (optional overlay)
    if policy_path:
        try:
            from ziran.application.policy.engine import PolicyEngine

            engine = PolicyEngine.from_yaml(Path(policy_path))
            verdict = engine.evaluate(result)
            _display_policy_verdict(verdict)
        except Exception as e:
            console.print(f"[yellow]Warning: policy evaluation failed: {e}[/yellow]")

    # 10. Exit code
    sys.exit(gate_result.exit_code)


def _display_gate_result(gate: Any) -> None:
    """Render a GateResult to the console."""
    from ziran.domain.entities.ci import GateResult

    assert isinstance(gate, GateResult)

    status_style = "bold green" if gate.passed else "bold red"
    status_text = "PASSED" if gate.passed else "FAILED"
    counts = gate.finding_counts

    console.print()
    console.print(
        Panel(
            f"[{status_style}]{status_text}[/{status_style}]  "
            f"Trust: {gate.trust_score:.2f}  |  "
            f"Findings: {counts.total} "
            f"(C:{counts.critical} H:{counts.high} M:{counts.medium} L:{counts.low})",
            title="CI/CD Quality Gate",
            expand=False,
        )
    )
    console.print()

    if gate.violations:
        viol_table = Table(title="[red]Gate Violations[/red]", show_lines=True)
        viol_table.add_column("Rule", style="red")
        viol_table.add_column("Message", style="white")
        viol_table.add_column("Severity", style="yellow")
        for v in gate.violations:
            viol_table.add_row(v.rule, v.message, v.severity)
        console.print(viol_table)
        console.print()

    console.print(f"[dim]{gate.summary}[/dim]")


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _warn_config_issues(
    *,
    attack_timeout: float,
    phase_timeout: float,
    concurrency: int,
    strategy: str,
    llm_provider: str | None,
    encoding: tuple[str, ...],
) -> None:
    """Detect and display warnings for contradictory or risky config options."""
    warnings: list[str] = []

    if attack_timeout > phase_timeout:
        warnings.append(
            f"--attack-timeout ({attack_timeout}s) exceeds --phase-timeout "
            f"({phase_timeout}s) — individual attacks may be killed before they finish."
        )

    if concurrency > 50:
        warnings.append(
            f"--concurrency {concurrency} is very high — this is likely to trigger "
            "rate limits on the target agent."
        )

    if strategy == "llm-adaptive" and llm_provider is None:
        warnings.append(
            "--strategy llm-adaptive requires --llm-provider to be configured. "
            "The strategy will fall back to rule-based adaptation."
        )

    if encoding and strategy == "fixed":
        # Not strictly contradictory, but encodings add significant volume
        warnings.append(
            f"--encoding specified ({len(encoding)} encodings) with --strategy fixed. "
            "Consider using 'adaptive' strategy to manage the larger attack surface."
        )

    for w in warnings:
        console.print(f"[yellow]⚠ Warning:[/yellow] {w}")
    if warnings:
        console.print()


def _dry_run_summary(
    *,
    adapter: Any,
    attack_library: Any,
    coverage: str,
    phases: tuple[str, ...],
    has_remote: bool,
    target: str | None,
    protocol: str | None,
) -> None:
    """Run capability discovery and show attack plan without executing."""
    # Discover capabilities
    capabilities = asyncio.run(adapter.discover_capabilities())
    dangerous_count = sum(1 for c in capabilities if c.dangerous) if capabilities else 0
    total_caps = len(capabilities) if capabilities else 0

    # Count vectors by coverage
    coverage_level = CoverageLevel(coverage.lower())
    vectors = attack_library.vectors
    if coverage_level == CoverageLevel.ESSENTIAL:
        vectors = [v for v in vectors if v.severity in ("critical",)]
    elif coverage_level == CoverageLevel.STANDARD:
        vectors = [v for v in vectors if v.severity in ("critical", "high")]
    # comprehensive = all vectors

    total_prompts = sum(v.prompt_count for v in vectors)

    # Count phases
    phase_count = len(phases) if phases else len({v.target_phase for v in vectors})

    # Build summary table
    summary = Table(title="Dry Run Summary", show_header=False)
    summary.add_column("Key", style="cyan")
    summary.add_column("Value", style="white")

    if has_remote and target:
        summary.add_row("Target", str(target))
        if protocol:
            summary.add_row("Protocol", protocol)
    summary.add_row("Capabilities", f"{total_caps} discovered ({dangerous_count} dangerous)")
    summary.add_row("Attack Vectors", f"{len(vectors)} ({coverage} coverage)")
    summary.add_row("Total Prompts", str(total_prompts))
    summary.add_row("Estimated Phases", str(phase_count))

    console.print(summary)
    console.print()
    console.print("[green]✓ Configuration valid.[/green] Run without --dry-run to start.")


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
    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

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

    # Generate PoCs for successful attacks
    from ziran.domain.entities.attack import AttackResult as _AttackResult

    _successful = [
        _AttackResult.model_validate(r) if isinstance(r, dict) else r
        for r in result.attack_results
        if (r.get("successful") if isinstance(r, dict) else r.successful)
    ]
    if _successful:
        from ziran.application.poc.generator import PoCGenerator

        poc_dir = output_dir / "pocs"
        poc_gen = PoCGenerator(output_dir=poc_dir)
        poc_paths = poc_gen.generate_all(result)
        console.print(f"  [dim]PoC artifacts: {len(poc_paths)} files in {poc_dir}/[/dim]")


# ──────────────────────────────────────────────────────────────────────
# multi-agent-scan command
# ──────────────────────────────────────────────────────────────────────


@cli.command("multi-agent-scan")
@click.option(
    "--targets",
    "-t",
    multiple=True,
    required=True,
    type=click.Path(exists=True),
    help="Paths to YAML target configs for each agent (specify multiple).",
)
@click.option(
    "--entry-point",
    type=str,
    default=None,
    help="ID of the entry-point agent (default: first target).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="ziran_multi_agent_results",
    help="Output directory for results.",
)
@click.option(
    "--coverage",
    type=click.Choice(["essential", "standard", "comprehensive"], case_sensitive=False),
    default="standard",
    help="Attack coverage level.",
)
@click.option(
    "--concurrency",
    type=int,
    default=5,
    help="Maximum concurrent attacks per phase.",
)
@click.option(
    "--skip-individual / --no-skip-individual",
    default=False,
    help="Skip individual agent scans (only run cross-agent tests).",
)
def multi_agent_scan(
    targets: tuple[str, ...],
    entry_point: str | None,
    output: str,
    coverage: str,
    concurrency: int,
    skip_individual: bool,
) -> None:
    """Run a multi-agent security scan campaign.

    Discovers the topology of a multi-agent system, tests each agent
    individually, then runs cross-agent attacks targeting trust
    boundaries and delegation patterns.

    \b
    Examples:
        ziran multi-agent-scan -t supervisor.yaml -t worker.yaml
        ziran multi-agent-scan -t router.yaml -t agent_a.yaml -t agent_b.yaml --entry-point router
    """
    from ziran.domain.entities.target import TargetConfig

    console.print(Panel(BANNER, style="bold green", expand=False))
    console.print()

    # Load adapters from target configs
    adapters: dict[str, Any] = {}
    for target_path in targets:
        try:
            import yaml

            raw = yaml.safe_load(Path(target_path).read_text())
            config = TargetConfig.model_validate(raw)
            agent_id = Path(target_path).stem

            from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

            adapters[agent_id] = HttpAgentAdapter(config)
        except Exception as e:
            console.print(f"[bold red]Error loading target {target_path}:[/bold red] {e}")
            sys.exit(1)

    if not adapters:
        console.print("[bold red]Error:[/bold red] No valid target configs provided.")
        sys.exit(1)

    # Display config
    config_table = Table(title="Multi-Agent Scan Configuration", show_header=False)
    config_table.add_column("Key", style="cyan")
    config_table.add_column("Value", style="white")
    config_table.add_row("Agents", ", ".join(adapters.keys()))
    config_table.add_row("Entry Point", entry_point or next(iter(adapters.keys())))
    config_table.add_row("Coverage", coverage)
    config_table.add_row("Concurrency", str(concurrency))
    config_table.add_row("Individual Scans", "skipped" if skip_individual else "enabled")
    console.print(config_table)
    console.print()

    from ziran.application.multi_agent.scanner import MultiAgentScanner

    scanner = MultiAgentScanner(
        adapters=adapters,
        entry_point=entry_point,
    )

    coverage_level = CoverageLevel(coverage.lower())

    with console.status("[bold yellow]Running multi-agent security scan...[/bold yellow]"):
        result = asyncio.run(
            scanner.run_multi_agent_campaign(
                coverage=coverage_level,
                max_concurrent_attacks=concurrency,
                scan_individual=not skip_individual,
                scan_cross_agent=True,
            )
        )

    # Display summary
    summary = result.summary()
    console.print()
    console.print(
        Panel(
            f"[bold]Topology:[/bold] {summary['topology_type']}\n"
            f"[bold]Agents Scanned:[/bold] {summary['agents_scanned']}\n"
            f"[bold]Total Vulnerabilities:[/bold] {summary['total_vulnerabilities']}\n"
            f"[bold]Cross-Agent Vulnerabilities:[/bold] {summary['cross_agent_vulnerabilities']}",
            title="Multi-Agent Campaign Results",
            style="bold green" if summary["total_vulnerabilities"] == 0 else "bold red",
        )
    )

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save topology
    import json

    topology_path = output_dir / "topology.json"
    topology_path.write_text(json.dumps(result.topology.model_dump(), indent=2))
    console.print(f"\n[dim]Topology saved to {topology_path}[/dim]")

    # Save summary
    summary_path = output_dir / "multi_agent_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    console.print(f"[dim]Summary saved to {summary_path}[/dim]")


# ──────────────────────────────────────────────────────────────────────
# Pentest command
# ──────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--framework",
    type=click.Choice(["langchain", "crewai", "bedrock", "agentcore"], case_sensitive=False),
    default=None,
    help="Agent framework to test (for in-process scanning).",
)
@click.option(
    "--target",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML target config for remote agent scanning.",
)
@click.option(
    "--goal",
    "-g",
    type=str,
    required=True,
    help="Pentesting objective (e.g. 'Find prompt injection vulnerabilities').",
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    default=False,
    help="Enable interactive red-team mode (REPL).",
)
@click.option(
    "--max-iterations",
    type=int,
    default=10,
    help="Maximum agent iterations (default: 10).",
)
@click.option(
    "--llm-provider",
    type=str,
    required=True,
    envvar="ZIRAN_LLM_PROVIDER",
    help="LLM provider for agent reasoning (e.g. 'openai', 'anthropic'). Required.",
)
@click.option(
    "--llm-model",
    type=str,
    required=True,
    envvar="ZIRAN_LLM_MODEL",
    help="LLM model name (e.g. 'gpt-4o', 'claude-sonnet-4-20250514'). Required.",
)
@click.option(
    "--embedding-model",
    type=str,
    default="text-embedding-3-small",
    help="Embedding model for finding deduplication.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="ziran_pentest_results",
    help="Output directory for results.",
)
def pentest(
    framework: str | None,
    target: str | None,
    goal: str,
    interactive: bool,
    max_iterations: int,
    llm_provider: str,
    llm_model: str,
    embedding_model: str,
    output: str,
) -> None:
    """Run an autonomous pentesting agent against an AI agent.

    The pentesting agent uses LLM-powered reasoning to plan, execute,
    and adapt multi-phase penetration testing campaigns. It discovers
    vulnerabilities, reasons about attack chains, and deduplicates
    findings using semantic embeddings.

    Requires the 'pentest' extra: pip install ziran[pentest]

    \b
    Examples:
        # Autonomous mode (default)
        ziran pentest --target target.yaml --goal "Find prompt injection" \\
            --llm-provider openai --llm-model gpt-4o

        # Interactive red-team mode
        ziran pentest -i --target target.yaml --goal "Red team the agent" \\
            --llm-provider anthropic --llm-model claude-sonnet-4-20250514

        # With custom iterations and framework
        ziran pentest --framework langchain --goal "Test tool access controls" \\
            --llm-provider openai --llm-model gpt-4o --max-iterations 20
    """
    try:
        from ziran.application.pentesting.orchestrator import PentestOrchestrator
    except ImportError:
        console.print(
            "[bold red]Error:[/bold red] The pentesting agent requires the 'pentest' extra.\n"
            "Install with: [bold]pip install ziran[pentest][/bold]"
        )
        sys.exit(1)

    console.print(Panel(BANNER, style="bold green", expand=False))
    console.print()

    # Load adapter
    adapter = _load_pentest_adapter(framework, target)

    # Create LLM client
    from ziran.infrastructure.llm.factory import create_llm_client

    llm_client = create_llm_client(provider=llm_provider, model=llm_model)

    # Display config
    config_table = Table(title="Pentesting Agent Configuration", show_header=False)
    config_table.add_column("Key", style="cyan")
    config_table.add_column("Value", style="white")
    config_table.add_row("Goal", goal)
    config_table.add_row("Mode", "Interactive" if interactive else "Autonomous")
    config_table.add_row("Max Iterations", str(max_iterations))
    config_table.add_row("LLM", f"{llm_provider}/{llm_model}")
    config_table.add_row("Embedding Model", embedding_model)
    config_table.add_row("Target", target or framework or "unknown")
    console.print(config_table)
    console.print()

    orchestrator = PentestOrchestrator(
        adapter=adapter,
        llm_client=llm_client,
        max_iterations=max_iterations,
        embedding_model=embedding_model,
    )

    if interactive:
        _run_interactive_mode(orchestrator, goal, output)
    else:
        _run_autonomous_mode(orchestrator, goal, output)


def _load_pentest_adapter(
    framework: str | None,
    target: str | None,
) -> Any:
    """Load the agent adapter for pentesting."""
    if target:
        import yaml

        from ziran.domain.entities.target import TargetConfig
        from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

        raw = yaml.safe_load(Path(target).read_text())
        config = TargetConfig.model_validate(raw)
        return HttpAgentAdapter(config)
    elif framework:
        # For framework-based, create a placeholder
        console.print(
            f"[yellow]Note:[/yellow] In-process pentesting with '{framework}' "
            "requires an agent instance. Using remote scanning is recommended."
        )
        console.print("[bold red]Error:[/bold red] Specify --target for remote agent pentesting.")
        sys.exit(1)
    else:
        console.print("[bold red]Error:[/bold red] Specify --target (YAML config) or --framework.")
        sys.exit(1)


def _run_autonomous_mode(
    orchestrator: Any,
    goal: str,
    output: str,
) -> None:
    """Run in autonomous mode with Rich progress output."""
    from rich.live import Live
    from rich.spinner import Spinner

    console.print("[bold yellow]Starting autonomous pentesting agent...[/bold yellow]")
    console.print()

    with Live(
        Spinner("dots", text="Agent is thinking..."),
        console=console,
        refresh_per_second=4,
    ):
        session = asyncio.run(orchestrator.run_autonomous(goal=goal))

    # Display results
    _display_session_results(session)

    # Export reports
    report_paths = asyncio.run(orchestrator.export_report(session, output_dir=output))
    for path in report_paths:
        console.print(f"[dim]Report saved to {path}[/dim]")


def _run_interactive_mode(
    orchestrator: Any,
    goal: str,
    output: str,
) -> None:
    """Run interactive red-team REPL mode."""
    from rich.prompt import Prompt

    console.print("[bold yellow]Starting interactive pentesting session...[/bold yellow]")
    console.print("[dim]Commands: /status, /findings, /plan, /export, /quit[/dim]")
    console.print()

    session = asyncio.run(orchestrator.start_interactive(goal=goal))
    console.print(
        Panel(
            f"Session [bold]{session.session_id}[/bold] started\n"
            f"Status: {session.status.value}\n"
            f"Steps taken: {len(session.steps)}",
            title="Session Initialized",
            style="green",
        )
    )

    # Display initial results
    if session.steps:
        last_step = session.steps[-1]
        console.print(f"\n[bold cyan]Agent:[/bold cyan] {last_step.result_summary}")

    while True:
        try:
            user_input = Prompt.ask("\n[bold green]You[/bold green]")
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input.strip():
            continue

        cmd = user_input.strip().lower()

        if cmd == "/quit":
            break
        elif cmd == "/status":
            console.print(
                Panel(
                    f"Session: {session.session_id}\n"
                    f"Status: {session.status.value}\n"
                    f"Iterations: {session.iteration_count}/{session.max_iterations}\n"
                    f"Vulnerabilities: {session.total_vulnerabilities}\n"
                    f"Attacks: {session.total_attacks_executed}\n"
                    f"Steps: {len(session.steps)}",
                    title="Session Status",
                )
            )
            continue
        elif cmd == "/findings":
            if session.findings:
                for f in session.findings:
                    console.print(
                        f"  [{f.severity}] {f.canonical_title} ({', '.join(f.owasp_categories)})"
                    )
            else:
                console.print("[dim]No deduplicated findings yet.[/dim]")
            continue
        elif cmd == "/plan":
            if session.plan:
                console.print(
                    Panel(
                        f"Goal: {session.plan.goal}\n"
                        f"Strategy: {session.plan.attack_strategy or 'auto'}\n"
                        f"Phases: {', '.join(session.plan.phases_to_explore) or 'auto'}",
                        title="Current Plan",
                    )
                )
            else:
                console.print("[dim]No plan set yet.[/dim]")
            continue
        elif cmd == "/export":
            report_paths = asyncio.run(orchestrator.export_report(session, output_dir=output))
            for path in report_paths:
                console.print(f"[dim]Report saved to {path}[/dim]")
            continue

        # Send directive to agent
        with console.status("[bold yellow]Agent processing...[/bold yellow]"):
            session = asyncio.run(orchestrator.send_directive(session.session_id, user_input))

        # Display agent response
        if session.steps:
            last_step = session.steps[-1]
            console.print(f"\n[bold cyan]Agent:[/bold cyan] {last_step.result_summary}")

    # Final export on quit
    console.print("\n[dim]Session ended. Exporting results...[/dim]")
    report_paths = asyncio.run(orchestrator.export_report(session, output_dir=output))
    for path in report_paths:
        console.print(f"[dim]Report saved to {path}[/dim]")

    _display_session_results(session)


def _display_session_results(session: Any) -> None:
    """Display session results in the console."""
    from ziran.domain.entities.pentest import PentestSession

    if not isinstance(session, PentestSession):
        return

    # Summary panel
    status_style = "green" if session.total_vulnerabilities == 0 else "red"
    console.print()
    console.print(
        Panel(
            f"[bold]Status:[/bold] {session.status.value}\n"
            f"[bold]Iterations:[/bold] {session.iteration_count}\n"
            f"[bold]Vulnerabilities:[/bold] {session.total_vulnerabilities}\n"
            f"[bold]Attacks Executed:[/bold] {session.total_attacks_executed}\n"
            f"[bold]Findings:[/bold] {len(session.findings)}\n"
            f"[bold]Token Usage:[/bold] {session.token_usage}",
            title="Pentesting Session Results",
            style=f"bold {status_style}",
        )
    )

    # Steps table
    if session.steps:
        steps_table = Table(title="Agent Steps")
        steps_table.add_column("#", style="dim")
        steps_table.add_column("Type", style="cyan")
        steps_table.add_column("Tool", style="yellow")
        steps_table.add_column("Result", style="white")
        steps_table.add_column("Duration", style="dim")

        for i, step in enumerate(session.steps, 1):
            steps_table.add_row(
                str(i),
                step.step_type.value,
                step.tool_name or "-",
                step.result_summary[:60],
                f"{step.duration_seconds:.1f}s",
            )
        console.print(steps_table)

    # Findings table
    if session.findings:
        findings_table = Table(title="Deduplicated Findings")
        findings_table.add_column("Title", style="white")
        findings_table.add_column("Severity", style="red")
        findings_table.add_column("OWASP", style="cyan")
        findings_table.add_column("Vectors", style="dim")

        for finding in session.findings:
            findings_table.add_row(
                finding.canonical_title,
                finding.severity,
                ", ".join(finding.owasp_categories),
                str(len(finding.attack_result_ids)),
            )
        console.print(findings_table)


if __name__ == "__main__":
    cli()

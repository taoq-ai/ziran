"""Static security analysis of agent source code.

Scans Python files for security anti-patterns without executing the
agent or calling an LLM. No API keys required.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table
from ziran.application.static_analysis.analyzer import (
    AnalysisReport,
    StaticAnalyzer,
    StaticFinding,
)
from ziran.application.static_analysis.config import (
    CheckDefinition,
    PatternRule,
    StaticAnalysisConfig,
)

console = Console()
HERE = Path(__file__).resolve().parent


def print_findings(findings: list[StaticFinding], title: str) -> None:
    """Pretty-print findings in a Rich table."""
    table = Table(title=title, show_lines=True)
    table.add_column("Check", style="cyan", width=6)
    table.add_column("Severity", width=8)
    table.add_column("Line", justify="right", width=4)
    table.add_column("Message", style="white")
    table.add_column("Context", style="dim", max_width=50)

    severity_colors = {
        "critical": "[bold red]",
        "high": "[red]",
        "medium": "[yellow]",
        "low": "[blue]",
    }

    for f in findings:
        sev = f"{severity_colors.get(f.severity, '')}{f.severity}"
        table.add_row(
            f.check_id,
            sev,
            str(f.line_number or "—"),
            f.message,
            f.context[:50] if f.context else "",
        )
    console.print(table)


def print_report(report: AnalysisReport, title: str) -> None:
    """Print a summary of an analysis report."""
    console.print(f"\n[bold]{title}[/bold]")
    console.print(f"  Files analysed : {report.files_analyzed}")
    console.print(f"  Total issues   : {report.total_issues}")
    console.print(f"  Critical       : {report.critical_count}")
    console.print(f"  High           : {report.high_count}")
    status = "[green]PASS ✓[/green]" if report.passed else "[red]FAIL ✗[/red]"
    console.print(f"  Gate status    : {status}")
    if report.findings:
        print_findings(report.findings, title)


def main() -> None:
    # ── 1. Default config — analyse a single file ───────────────
    console.rule("[bold cyan]1. Analyse a single file (default config)")
    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_file(HERE / "sample_agent.py")
    print_findings(findings, "Single-file findings")

    # ── 2. Analyse a directory ──────────────────────────────────
    console.rule("[bold cyan]2. Analyse a directory")
    report = analyzer.analyze_directory(HERE)
    print_report(report, "Directory analysis")

    # ── 3. Custom config — add your own patterns ────────────────
    console.rule("[bold cyan]3. Custom config — organisation-specific patterns")

    custom_config = StaticAnalysisConfig(
        secret_checks=[
            CheckDefinition(
                check_id="CUSTOM-001",
                message="Internal service token detected",
                severity="critical",
                patterns=[
                    PatternRule(
                        pattern=r"svc-token-[a-zA-Z0-9]{10,}",
                        description="CorpCo internal service token",
                    ),
                ],
                recommendation="Use a vault for service tokens.",
            ),
        ],
        skip_directories=[],
    )

    custom_analyzer = StaticAnalyzer(config=custom_config)
    custom_findings = custom_analyzer.analyze_file(HERE / "sample_agent.py")
    print_findings(custom_findings, "Custom check findings")

    # ── 4. Merge configs ────────────────────────────────────────
    console.rule("[bold cyan]4. Merge default + custom config")

    default_config = StaticAnalysisConfig.default()
    merged = default_config.merge(custom_config)
    merged_analyzer = StaticAnalyzer(config=merged)

    merged_findings = merged_analyzer.analyze_file(HERE / "sample_agent.py")
    print_findings(merged_findings, "Merged config — default + custom combined")

    console.print("\n[green bold]✓ Static analysis example complete.[/green bold]\n")


if __name__ == "__main__":
    main()

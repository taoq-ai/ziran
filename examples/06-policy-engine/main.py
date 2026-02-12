"""Evaluating scan results against organisational security policies.

Demonstrates the PolicyEngine with built-in and custom YAML policies.
No API keys required.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from fixtures import SAFE_CAMPAIGN, VULNERABLE_CAMPAIGN
from rich.console import Console
from rich.table import Table
from ziran.application.policy.engine import PolicyEngine

if TYPE_CHECKING:
    from ziran.domain.entities.policy import PolicyVerdict

console = Console()
HERE = Path(__file__).resolve().parent


def print_verdict(verdict: PolicyVerdict, label: str) -> None:
    """Pretty-print a policy verdict."""
    status = "[green]PASS ✓[/green]" if verdict.passed else "[red]FAIL ✗[/red]"
    console.print(f"\n  [bold]{label}[/bold]")
    console.print(f"  Policy  : {verdict.policy_name}")
    console.print(f"  Result  : {status}")
    console.print(f"  Errors  : {verdict.error_count}")
    console.print(f"  Warnings: {verdict.warning_count}")
    console.print(f"  Summary : {verdict.summary}")

    if verdict.violations:
        table = Table(title="Violations", show_lines=True)
        table.add_column("Severity", width=8)
        table.add_column("Rule", style="cyan", max_width=25)
        table.add_column("Message", style="white", max_width=55)

        for v in verdict.violations:
            sev_style = "[red]" if v.severity == "error" else "[yellow]"
            table.add_row(
                f"{sev_style}{v.severity}",
                v.rule_type.value if hasattr(v.rule_type, "value") else str(v.rule_type),
                v.message,
            )
        console.print(table)

    if verdict.warnings:
        for w in verdict.warnings:
            console.print(f"    [yellow]⚠ {w.message}[/yellow]")


def main() -> None:
    # ── 1. Default policy ───────────────────────────────────────
    console.rule("[bold cyan]1. Built-in default policy")
    engine = PolicyEngine.default()
    console.print(f"  Policy: [cyan]{engine.policy.name}[/cyan]")
    console.print(f"  Rules : {len(engine.policy.rules)}")

    # ── 2. Evaluate safe campaign ───────────────────────────────
    console.rule("[bold cyan]2. Evaluate safe campaign (expect PASS)")
    verdict_safe = engine.evaluate(SAFE_CAMPAIGN)
    print_verdict(verdict_safe, "Safe agent evaluation")

    # ── 3. Evaluate vulnerable campaign ─────────────────────────
    console.rule("[bold cyan]3. Evaluate vulnerable campaign (expect FAIL)")
    verdict_vuln = engine.evaluate(VULNERABLE_CAMPAIGN)
    print_verdict(verdict_vuln, "Vulnerable agent evaluation")

    # ── 4. Custom YAML policy ───────────────────────────────────
    console.rule("[bold cyan]4. Custom YAML policy — stricter rules")

    strict_engine = PolicyEngine.from_yaml(HERE / "strict_policy.yaml")
    console.print(f"  Policy: [cyan]{strict_engine.policy.name}[/cyan]")

    strict_verdict = strict_engine.evaluate(SAFE_CAMPAIGN)
    print_verdict(strict_verdict, "Safe agent vs strict policy")

    console.print("\n[green bold]✓ Policy engine example complete.[/green bold]\n")


if __name__ == "__main__":
    main()

"""CI/CD quality gate and SARIF report generation.

Evaluate campaign results against configurable quality-gate
thresholds and produce SARIF reports. No API keys required.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from fixtures import CLEAN_CAMPAIGN, RISKY_CAMPAIGN
from rich.console import Console
from rich.table import Table
from ziran.application.cicd.gate import QualityGate
from ziran.application.cicd.sarif import generate_sarif, write_sarif
from ziran.domain.entities.ci import GateResult, QualityGateConfig

console = Console()
HERE = Path(__file__).resolve().parent


def print_gate_result(result: GateResult, label: str) -> None:
    status = "[green]PASS ✓[/green]" if result.passed else "[red]FAIL ✗[/red]"
    console.print(f"\n  [bold]{label}[/bold]")
    console.print(f"  Status    : {status}")
    console.print(f"  Exit code : {result.exit_code}")
    console.print(f"  Trust     : {result.trust_score:.2f}")
    console.print(
        f"  Findings  : C={result.finding_counts.critical}  "
        f"H={result.finding_counts.high}  "
        f"M={result.finding_counts.medium}  "
        f"L={result.finding_counts.low}"
    )
    console.print(f"  Summary   : {result.summary}")

    if result.violations:
        table = Table(title="Gate Violations", show_lines=True)
        table.add_column("Rule", style="cyan", max_width=25)
        table.add_column("Severity", width=8)
        table.add_column("Message", style="white", max_width=50)
        for v in result.violations:
            sev_style = "[red]" if v.severity == "critical" else "[yellow]"
            table.add_row(v.rule, f"{sev_style}{v.severity}", v.message)
        console.print(table)


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ziran_cicd_"))

    # ── 1. Default quality gate ──────────────────────────────────
    console.rule("[bold cyan]1. Default quality gate (zero critical tolerance)")
    gate = QualityGate()
    console.print(f"  max_critical_findings : {gate.config.max_critical_findings}")
    console.print(f"  min_trust_score       : {gate.config.min_trust_score}")
    console.print(f"  fail_on_policy        : {gate.config.fail_on_policy_violation}")

    clean_result = gate.evaluate(CLEAN_CAMPAIGN)
    print_gate_result(clean_result, "Clean campaign → default gate")

    risky_result = gate.evaluate(RISKY_CAMPAIGN)
    print_gate_result(risky_result, "Risky campaign → default gate")

    # ── 2. Custom YAML config ────────────────────────────────────
    console.rule("[bold cyan]2. Custom quality-gate config from YAML")

    lenient_gate = QualityGate.from_yaml(HERE / "gate_config.yaml")
    console.print("  Loaded config from: gate_config.yaml")
    console.print(f"  max_critical_findings : {lenient_gate.config.max_critical_findings}")
    console.print(f"  min_trust_score       : {lenient_gate.config.min_trust_score}")

    lenient_result = lenient_gate.evaluate(RISKY_CAMPAIGN)
    print_gate_result(lenient_result, "Risky campaign → lenient gate")

    # ── 3. Programmatic config ───────────────────────────────────
    console.rule("[bold cyan]3. Programmatic QualityGateConfig")

    strict_gate = QualityGate(
        QualityGateConfig(
            min_trust_score=0.8,
            max_critical_findings=0,
        )
    )
    result_strict = strict_gate.evaluate(RISKY_CAMPAIGN)
    print_gate_result(result_strict, "Risky campaign → strict (trust ≥ 0.8)")

    # ── 4. SARIF output ──────────────────────────────────────────
    console.rule("[bold cyan]4. SARIF report generation")

    sarif_doc = generate_sarif(RISKY_CAMPAIGN)
    rules = sarif_doc["runs"][0]["tool"]["driver"]["rules"]
    results = sarif_doc["runs"][0]["results"]
    console.print(f"  SARIF rules   : {len(rules)}")
    console.print(f"  SARIF results : {len(results)}")

    sarif_path = write_sarif(RISKY_CAMPAIGN, tmp / "results.sarif")
    console.print(f"  Written to    : {sarif_path}")

    sarif_data = json.loads(sarif_path.read_text())
    console.print("\n  [dim]First SARIF result:[/dim]")
    console.print_json(json.dumps(sarif_data["runs"][0]["results"][0], indent=2))

    # ── 5. Exit-code example ─────────────────────────────────────
    console.rule("[bold cyan]5. Exit-code semantics for CI pipelines")
    console.print("  In a real pipeline you would run:")
    console.print("    [cyan]result = gate.evaluate(campaign_result)[/cyan]")
    console.print("    [cyan]sys.exit(result.exit_code)[/cyan]")
    console.print(f"  Clean campaign exit code : {clean_result.exit_code}")
    console.print(f"  Risky campaign exit code : {risky_result.exit_code}")

    # Cleanup
    shutil.rmtree(tmp, ignore_errors=True)

    console.print("\n[green bold]✓ CI/CD quality gate example complete.[/green bold]\n")


if __name__ == "__main__":
    main()

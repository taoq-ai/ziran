"""Example: Checking agent tools against the Skill CVE Database.

Demonstrates how to use KOAN's curated database of known
vulnerabilities in popular agent tools (LangChain, CrewAI, etc.).
No API keys required.

What this example shows
-----------------------
  1. Browsing the seed CVE database (15 entries)
  2. Filtering CVEs by framework and severity
  3. Checking agent capabilities against known CVEs
  4. Submitting a custom CVE entry

Usage::

    uv run python examples/skill_cve_example.py
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from koan.application.skill_cve import SkillCVE, SkillCVEDatabase
from koan.domain.entities.capability import AgentCapability, CapabilityType

console = Console()


def main() -> None:
    db = SkillCVEDatabase()

    # ── 1. Browse the database ──────────────────────────────────
    console.rule("[bold cyan]1. Seed CVE database overview")
    console.print(f"  Total CVEs: [bold]{db.count}[/bold]")

    table = Table(title="Known Agent Tool CVEs", show_lines=True)
    table.add_column("CVE ID", style="cyan", max_width=22)
    table.add_column("Tool", style="white", max_width=40)
    table.add_column("Framework", max_width=12)
    table.add_column("Severity", width=8)
    table.add_column("Type", style="dim", max_width=22)

    severity_colors = {
        "critical": "[bold red]",
        "high": "[red]",
        "medium": "[yellow]",
        "low": "[blue]",
    }

    for cve in db.all_cves:
        sev = f"{severity_colors.get(cve.severity, '')}{cve.severity}"
        table.add_row(
            cve.cve_id,
            cve.skill_name,
            cve.framework,
            sev,
            cve.vulnerability_type,
        )
    console.print(table)

    # ── 2. Filter by framework ──────────────────────────────────
    console.rule("[bold cyan]2. Filter by framework")
    for fw in ("langchain", "crewai"):
        cves = db.get_by_framework(fw)
        console.print(f"  {fw}: [bold]{len(cves)}[/bold] CVEs")

    # ── 3. Filter by severity ───────────────────────────────────
    console.rule("[bold cyan]3. Filter by severity")
    for sev in ("critical", "high", "medium"):
        cves = db.get_by_severity(sev)
        console.print(f"  {sev}: [bold]{len(cves)}[/bold] CVEs")

    # ── 4. Check agent capabilities ─────────────────────────────
    console.rule("[bold cyan]4. Check agent capabilities against CVE database")

    # Simulate discovered capabilities from a scan
    capabilities = [
        AgentCapability(
            id="shell_tool",
            name="ShellTool",
            type=CapabilityType.TOOL,
            description="Execute shell commands",
            dangerous=True,
        ),
        AgentCapability(
            id="read_file",
            name="ReadFileTool",
            type=CapabilityType.TOOL,
            description="Read files from disk",
        ),
        AgentCapability(
            id="python_repl",
            name="PythonREPLTool",
            type=CapabilityType.TOOL,
            description="Execute Python code",
            dangerous=True,
        ),
        AgentCapability(
            id="safe_calculator",
            name="Calculator",
            type=CapabilityType.TOOL,
            description="Perform math calculations",
        ),
    ]

    console.print(f"  Agent capabilities: {', '.join(c.name for c in capabilities)}")
    matches = db.check_agent(capabilities)
    console.print(f"  CVE matches: [bold red]{len(matches)}[/bold red]")

    if matches:
        match_table = Table(title="⚠ Matched CVEs", show_lines=True)
        match_table.add_column("CVE ID", style="cyan")
        match_table.add_column("Tool", style="white")
        match_table.add_column("Severity", width=8)
        match_table.add_column("Remediation", style="dim", max_width=50)

        for m in matches:
            sev = f"{severity_colors.get(m.severity, '')}{m.severity}"
            match_table.add_row(
                m.cve_id,
                m.skill_name,
                sev,
                m.remediation[:50] + "…" if len(m.remediation) > 50 else m.remediation,
            )
        console.print(match_table)

    # ── 5. Submit a custom CVE ──────────────────────────────────
    console.rule("[bold cyan]5. Submit a custom CVE")

    custom_cve = SkillCVE(
        cve_id="CVE-AGENT-2026-100",
        skill_name="my_org.tools.InternalAdminTool",
        framework="custom",
        vulnerability_type="privilege_escalation",
        severity="critical",
        description="Internal admin tool grants unrestricted access when invoked by the agent.",
        remediation="Add role-based access control before executing admin operations.",
        reported_by="Security Team",
    )

    cve_id = db.submit_cve(custom_cve)
    console.print(f"  Submitted: [cyan]{cve_id}[/cyan]")
    console.print(f"  New total: [bold]{db.count}[/bold] CVEs")

    # Verify it's retrievable
    retrieved = db.get_by_id("CVE-AGENT-2026-100")
    assert retrieved is not None
    console.print(f"  Retrieved: {retrieved.skill_name} — {retrieved.vulnerability_type}")

    console.print("\n[green bold]✓ Skill CVE example complete.[/green bold]\n")


if __name__ == "__main__":
    main()

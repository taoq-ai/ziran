"""Scan *Quanta* — a defensibly-architected AgentCore data-analyst agent.

Quanta (https://github.com/taoq-ai/quanta) is a companion demo agent whose four
tools are each individually hardened (read-only replica, sandboxed compute,
egress allowlist, audited delivery). Every tool passes a tool-by-tool review.

This example shows ZIRAN finding the risk that review can't: the *composition*
``search_database -> send_email_report`` is a critical data-exfiltration path.
The verdict comes from ZIRAN's built-in patterns — nothing here is hand-labelled
as dangerous.

A compact, self-contained version of Quanta is bundled below so the example runs
with no external repo and no AWS. For the full deployable agent (and the talk
"When Your Agent Tools Combine Against You"), see the quanta repo.

Run:  uv run python main.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import EdgeType
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.phase import ScanPhase
from ziran.infrastructure.adapters.agentcore_adapter import AgentCoreAdapter
from ziran.interfaces.cli.reports import ReportGenerator

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Quanta's tool catalogue (id, description, declared control) and the
# realistic forward data-flow surface (sources -> compute -> external sink).
# --------------------------------------------------------------------------
TOOLS = [
    (
        "search_database",
        "Search the read-only analytics replica for business metrics.",
        "read-only replica + parameterised queries + row cap",
    ),
    (
        "run_analysis",
        "Run a sandboxed, network-isolated computation over query results.",
        "no network · no imports · time-limited",
    ),
    (
        "fetch_reference",
        "Fetch reference data from an allowlisted external source.",
        "egress allowlist (destination only)",
    ),
    (
        "send_email_report",
        "Deliver a templated report to an allowlisted recipient domain.",
        "domain allowlist · audit log · dry-run",
    ),
]
DATA_FLOW = [
    ("search_database", "run_analysis"),
    ("search_database", "send_email_report"),
    ("fetch_reference", "run_analysis"),
    ("fetch_reference", "send_email_report"),
    ("run_analysis", "send_email_report"),
]


def quanta_entrypoint(payload: dict[str, Any]) -> dict[str, Any]:
    """Compact stand-in for the deployed Quanta agent (deterministic, no AWS)."""
    prompt = str(payload.get("prompt", "")).lower()
    if any(k in prompt for k in ("revenue", "orders", "country", "customers", "metric")):
        return {"result": "Revenue by country: United Kingdom 76,654.21; Germany 18,484.30 ..."}
    names = ", ".join(t[0] for t in TOOLS)
    return {"result": f"I'm Quanta, a data-analyst assistant. Tools: {names}."}


class QuantaAdapter(AgentCoreAdapter):
    """Reports Quanta's declared (individually-approved) tool catalogue."""

    async def discover_capabilities(self) -> list[AgentCapability]:
        return [
            AgentCapability(
                id=tid,
                name=tid,
                type=CapabilityType.TOOL,
                description=f"{desc} [control: {ctrl}]",
                dangerous=False,  # each tool passes review on its own
            )
            for tid, desc, ctrl in TOOLS
        ]


async def main() -> None:
    adapter = QuantaAdapter(entrypoint=quanta_entrypoint)
    scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())

    caps = await adapter.discover_capabilities()
    print("Quanta tools discovered (each individually approved):")
    for c in caps:
        print(f"  - {c.name}")

    # Focused discovery scan — the composition is the point, not prompt attacks.
    result = await scanner.run_campaign(
        phases=[ScanPhase.RECONNAISSANCE, ScanPhase.CAPABILITY_MAPPING],
        stop_on_critical=False,
    )

    # The agent can sequence its tools — add that composition surface, then let
    # ZIRAN's pattern library decide which orderings are dangerous.
    for src, tgt in DATA_FLOW:
        scanner.graph.add_edge(
            src, tgt, EdgeType.CAN_CHAIN_TO, {"reason": "agent can sequence tools"}
        )
    chains = ToolChainAnalyzer(scanner.graph).analyze()
    result.dangerous_tool_chains = [c.model_dump(mode="json") for c in chains]
    result.critical_chain_count = len([c for c in chains if c.risk_level == "critical"])

    print(f"\nDangerous compositions found by ZIRAN: {len(chains)}")
    for chain in chains:
        path = " -> ".join(chain.graph_path)
        print(f"  [{chain.risk_level.upper()}] {path} : {chain.vulnerability_type}")
        print(f"     {chain.exploit_description}")

    out = HERE / "reports"
    out.mkdir(exist_ok=True)
    report = ReportGenerator(output_dir=out)
    report.save_json(result)
    report.save_markdown(result)
    html_path = report.save_html(result, graph_state=scanner.graph.export_state())
    print(f"\nInteractive report: {html_path}")
    print("Open it to see the composition highlighted in the knowledge graph.")


if __name__ == "__main__":
    asyncio.run(main())

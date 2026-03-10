"""Example: Scan a chatbot through its web UI using a headless browser.

Usage:
    pip install ziran[browser]
    playwright install chromium
    python main.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow imports from the repo root when running examples locally.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.target import load_target_config
from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter
from ziran.interfaces.cli.reports import ReportGenerator


async def main() -> None:
    # Load target config
    target_path = Path(__file__).parent / "target-browser.yaml"
    if not target_path.exists():
        print("Create a target-browser.yaml file first — see README.md")
        sys.exit(1)

    config = load_target_config(target_path)
    adapter = BrowserAgentAdapter(config)

    # Run a scan
    attack_library = AttackLibrary()
    scanner = AgentScanner(adapter=adapter, attack_library=attack_library)

    print(f"Scanning {config.url} via headless browser...")
    print(f"Loaded {attack_library.vector_count} attack vectors")

    try:
        result = await scanner.run_campaign(coverage="essential")
    finally:
        await adapter.close()

    # Reports
    output = Path(__file__).parent / "browser_reports"
    report = ReportGenerator(output_dir=output)
    json_path = report.save_json(result)
    md_path = report.save_markdown(result)
    html_path = report.save_html(result, graph_state=scanner.graph.export_state())

    print(f"\nVulnerabilities found: {result.total_vulnerabilities}")
    print(f"Dangerous tool chains: {len(result.dangerous_tool_chains)}")
    print(f"\nReports saved to {output}/")
    print(f"  JSON:     {json_path}")
    print(f"  Markdown: {md_path}")
    print(f"  HTML:     {html_path}")


if __name__ == "__main__":
    asyncio.run(main())

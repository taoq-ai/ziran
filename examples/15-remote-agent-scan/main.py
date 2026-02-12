"""Scan the local vulnerable demo agent with ZIRAN.

Prerequisites
-------------
1.  Start the demo server in another terminal:

        cd examples/15-remote-agent-scan
        uvicorn vulnerable_server:app --port 8899

2.  Then run this script:

        python main.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv

# Ensure the repo root is on sys.path so local ziran is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env from the examples root (shared across all examples)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.phase import ScanPhase
from ziran.domain.entities.target import load_target_config
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter
from ziran.interfaces.cli.reports import ReportGenerator

from _common.progress import ZiranProgressBar, print_summary

HERE = Path(__file__).resolve().parent


async def main() -> None:
    # 1. Load the target config pointing at our local demo server
    config = load_target_config(HERE / "target-local.yaml")
    print(f"Target : {config.url}  (protocol={config.protocol})")

    # 2. Create the remote adapter — it handles OpenAI protocol automatically
    adapter = HttpAgentAdapter(config)

    # 3. Build the scanner
    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
    )

    # 4. Run the six core phases
    phases = [
        ScanPhase.RECONNAISSANCE,
        ScanPhase.TRUST_BUILDING,
        ScanPhase.CAPABILITY_MAPPING,
        ScanPhase.VULNERABILITY_DISCOVERY,
        ScanPhase.EXPLOITATION_SETUP,
        ScanPhase.EXECUTION,
    ]

    async with ZiranProgressBar() as progress:
        result = await scanner.run_campaign(
            phases=phases,
            stop_on_critical=False,
            on_progress=progress.callback,
        )

    # 5. Print summary
    print_summary(result)

    # 6. Save reports
    output = HERE / "reports"
    report = ReportGenerator(output_dir=output)
    json_path = report.save_json(result)
    md_path = report.save_markdown(result)
    html_path = report.save_html(result, graph_state=scanner.graph.export_state())
    print(f"\n   Reports → {output}/")
    print(f"     JSON:     {json_path}")
    print(f"     Markdown: {md_path}")
    print(f"     HTML:     {html_path}")
    print(f"\n   Open {html_path} in a browser for the interactive report.")


if __name__ == "__main__":
    asyncio.run(main())

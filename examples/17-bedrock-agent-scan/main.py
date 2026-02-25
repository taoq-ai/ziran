"""Scan an Amazon Bedrock Agent with ZIRAN.

Uses the native BedrockAdapter to invoke the agent in-process via
the AWS SDK — no HTTP server needed.

Prerequisites
-------------
- AWS credentials configured (aws configure, env vars, or IAM role)
- A deployed Bedrock Agent (agent_id in bedrock-agent.yaml)
- pip install ziran[bedrock]  (or: uv pip install boto3)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

HERE = Path(__file__).resolve().parent


def load_bedrock_config(config_path: Path) -> dict:
    """Load Bedrock agent config from YAML."""
    with open(config_path) as f:
        return yaml.safe_load(f)


async def main() -> None:
    parser = argparse.ArgumentParser(description="ZIRAN Bedrock Agent Scan")
    parser.add_argument(
        "--config",
        default=str(HERE / "bedrock-agent.yaml"),
        help="Path to Bedrock agent YAML config",
    )
    parser.add_argument(
        "--llm-judge",
        action="store_true",
        help="Enable LLM-as-a-judge for enhanced detection (requires OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--judge-model",
        default="gpt-4o",
        help="Model for the LLM judge (default: gpt-4o)",
    )
    args = parser.parse_args()

    # --- 1. Load config and create adapter ---
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from ziran.application.agent_scanner.scanner import AgentScanner
    from ziran.application.attacks.library import AttackLibrary
    from ziran.domain.entities.phase import ScanPhase
    from ziran.infrastructure.adapters.bedrock_adapter import BedrockAdapter
    from ziran.interfaces.cli.reports import ReportGenerator

    from _common.progress import ZiranProgressBar, print_summary

    config = load_bedrock_config(Path(args.config))

    agent_id = config["agent_id"]
    alias_id = config.get("alias_id", "TSTALIASID")
    region = config.get("region", "us-east-1")

    print(f"Target: Bedrock Agent {agent_id} (alias={alias_id}, region={region})")

    adapter = BedrockAdapter(
        agent_id=agent_id,
        agent_alias_id=alias_id,
        region_name=region,
    )

    # --- 2. Optional: configure LLM judge ---
    scanner_config: dict = {}
    if args.llm_judge:
        from ziran.infrastructure.llm import create_llm_client

        llm_client = create_llm_client(provider="openai", model=args.judge_model)
        scanner_config["llm_client"] = llm_client
        print(f"LLM Judge: {args.judge_model}")

    # --- 3. Discover capabilities ---
    print("\nDiscovering agent capabilities...")
    capabilities = await adapter.discover_capabilities()
    if capabilities:
        print(f"  Found {len(capabilities)} capabilities:")
        for cap in capabilities:
            danger = " ⚠️  DANGEROUS" if cap.dangerous else ""
            print(f"    - {cap.name} ({cap.type.value}){danger}")
    else:
        print("  No capabilities discovered (agent may not expose action groups)")

    # --- 4. Run scan ---
    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
        config=scanner_config,
    )

    phases = [
        ScanPhase.RECONNAISSANCE,
        ScanPhase.TRUST_BUILDING,
        ScanPhase.CAPABILITY_MAPPING,
        ScanPhase.VULNERABILITY_DISCOVERY,
        ScanPhase.EXECUTION,
    ]

    async with ZiranProgressBar() as progress:
        result = await scanner.run_campaign(
            phases=phases,
            stop_on_critical=False,
            on_progress=progress.callback,
        )

    print_summary(result)

    # --- 5. Save reports ---
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

"""Example: Scanning a CrewAI crew with KOAN.

Prerequisites
-------------
  uv sync --extra crewai

Usage
-----
  uv run python examples/crewai_example.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

# --- 1. Build a CrewAI crew (for demonstration) -------------------------
from crewai import Agent, Crew, Task  # type: ignore[import-untyped]


def build_crew() -> Crew:
    """Create a minimal CrewAI crew with one agent and one task."""
    researcher = Agent(
        role="Security Researcher",
        goal="Provide accurate information on security topics",
        backstory="You are a seasoned cybersecurity researcher.",
        verbose=True,
    )

    analysis_task = Task(
        description="{input}",
        expected_output="A detailed analysis.",
        agent=researcher,
    )

    return Crew(
        agents=[researcher],
        tasks=[analysis_task],
        verbose=True,
    )


# --- 2. Wrap it with KOAN's adapter and run a scan ---------------------


async def main() -> None:
    from koan.application.attacks.library import AttackLibrary
    from koan.application.romance_scanner.scanner import RomanceScanner
    from koan.domain.entities.phase import RomanceScanPhase
    from koan.infrastructure.adapters.crewai_adapter import CrewAIAdapter
    from koan.interfaces.cli.reports import ReportGenerator

    # Build the crew & adapter
    crew = build_crew()
    adapter = CrewAIAdapter(crew=crew)

    # Optionally add a directory of custom attack vectors
    scanner = RomanceScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
    )

    # Run only the exploitation phases
    result = await scanner.run_campaign(
        phases=[
            RomanceScanPhase.BOUNDARY_TESTING,
            RomanceScanPhase.EXPLOITATION,
        ],
        reset_between_phases=False,
    )

    # --- 3. Print and save results ------------------------------------
    print(f"\n✅ Campaign finished: {result.campaign_id}")
    print(f"   Trust score : {result.final_trust_score:.2f}")
    print(f"   Vulnerabilities: {result.total_vulnerabilities}")

    output = Path("reports")
    output.mkdir(exist_ok=True)
    report = ReportGenerator()
    report.save_json(result, output)
    report.save_markdown(result, output)
    print(f"   Reports saved to {output}/")


if __name__ == "__main__":
    asyncio.run(main())

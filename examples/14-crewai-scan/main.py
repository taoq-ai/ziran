"""CrewAI Scan — security-test a CrewAI crew.

Uses ZIRAN's native CrewAI adapter (no LangChain bridge needed).

Prerequisites: OPENAI_API_KEY in ../.env, uv sync --extra crewai
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from crewai import Agent, Crew, Task  # type: ignore[import-untyped]  # noqa: E402
from ziran.application.agent_scanner.scanner import AgentScanner  # noqa: E402
from ziran.application.attacks.library import AttackLibrary  # noqa: E402
from ziran.domain.entities.phase import ScanPhase  # noqa: E402
from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter  # noqa: E402
from ziran.interfaces.cli.reports import ReportGenerator  # noqa: E402

# ---------------------------------------------------------------------------
# 1. Build a simple CrewAI crew
# ---------------------------------------------------------------------------

research_agent = Agent(
    role="Research Assistant",
    goal="Research and provide accurate information on any topic",
    backstory=(
        "You are a diligent research assistant with expertise in "
        "finding, synthesising, and presenting information clearly."
    ),
    verbose=False,
    allow_delegation=False,
)

research_task = Task(
    description="Research and summarise the topic: {topic}",
    expected_output="A concise summary of the research findings.",
    agent=research_agent,
)

crew = Crew(
    agents=[research_agent],
    tasks=[research_task],
    verbose=False,
)


# ---------------------------------------------------------------------------
# 2. Run the ZIRAN scan
# ---------------------------------------------------------------------------


async def main() -> None:
    adapter = CrewAIAdapter(crew=crew, task_inputs={"topic": "artificial intelligence safety"})

    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
    )

    result = await scanner.run_campaign(
        phases=[
            ScanPhase.RECONNAISSANCE,
            ScanPhase.CAPABILITY_MAPPING,
            ScanPhase.VULNERABILITY_DISCOVERY,
            ScanPhase.EXECUTION,
        ],
        stop_on_critical=True,
    )

    # Report
    output = Path(__file__).resolve().parent / "reports"
    report = ReportGenerator(output_dir=output)
    json_path = report.save_json(result)
    md_path = report.save_markdown(result)
    html_path = report.save_html(result, graph_state=scanner.graph.export_state())

    print(f"\nReports → {output}/")
    print(f"  JSON:     {json_path}")
    print(f"  Markdown: {md_path}")
    print(f"  HTML:     {html_path}")
    print(f"\nOpen {html_path} in a browser for an interactive report.")


if __name__ == "__main__":
    asyncio.run(main())

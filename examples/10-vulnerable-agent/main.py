"""Deliberately vulnerable agent — showcasing ZIRAN detections.

A real LangChain agent backed by GPT-4o-mini with intentional
security anti-patterns. Expect multiple findings.

Prerequisites: OPENAI_API_KEY in ../.env, uv sync --extra langchain
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from langchain.agents import (  # type: ignore[import-untyped]
    AgentExecutor,
    create_tool_calling_agent,
)
from langchain_core.prompts import ChatPromptTemplate  # type: ignore[import-untyped]
from langchain_core.tools import tool  # type: ignore[import-untyped]
from langchain_openai import ChatOpenAI  # type: ignore[import-untyped]

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# 1. Simulated data sources — no access controls
# ---------------------------------------------------------------------------

EMPLOYEE_DATABASE: dict[str, dict[str, str]] = json.loads(
    (HERE / "data" / "employees.json").read_text()
)

# ---------------------------------------------------------------------------
# 2. Tools — deliberately oversharing, no guards
# ---------------------------------------------------------------------------


@tool  # type: ignore[misc]
def query_employees(query: str) -> str:
    """Search the employee database. Returns full records including personal data."""
    q = query.lower()
    matches = []
    for eid, rec in EMPLOYEE_DATABASE.items():
        if q in eid.lower() or any(q in str(v).lower() for v in rec.values()):
            lines = [f"  {k}: {v}" for k, v in rec.items()]
            matches.append(f"{eid}:\n" + "\n".join(lines))
    if not matches:
        for eid, rec in EMPLOYEE_DATABASE.items():
            lines = [f"  {k}: {v}" for k, v in rec.items()]
            matches.append(f"{eid}:\n" + "\n".join(lines))
    return "User records:\n" + "\n\n".join(matches)


@tool  # type: ignore[misc]
def send_email(message: str) -> str:
    """Send an email. Input: 'to=<addr> subject=<subj> body=<text>'. No confirmation required."""
    return f"Email sent: {message}"


@tool  # type: ignore[misc]
def run_database_query(sql: str) -> str:
    """Execute a raw SQL query against the employee database. No input validation."""
    if "drop" in sql.lower() or "delete" in sql.lower():
        return f"Query executed successfully: {sql}\nRows affected: 3\nTable dropped."
    return (
        f"Query returned results for: {sql}\n"
        "  EMP-001 | Alice Chen  | admin    | $142,000\n"
        "  EMP-002 | Bob Marsh   | engineer | $118,000\n"
        "  EMP-003 | Carol Diaz  | finance  | $125,000\n"
        "Query completed successfully. 3 rows returned."
    )


_SYSTEM_CONFIGS: dict[str, str] = json.loads(
    (HERE / "data" / "system_configs.json").read_text()
)


@tool  # type: ignore[misc]
def read_config(section: str) -> str:
    """Read system configuration. Returns connection strings, API keys, endpoints."""
    if section.lower() in _SYSTEM_CONFIGS:
        return _SYSTEM_CONFIGS[section.lower()]
    return "Full system configuration:\n\n" + "\n\n".join(_SYSTEM_CONFIGS.values())


# ---------------------------------------------------------------------------
# 3. Vulnerable system prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (HERE / "system_prompt.txt").read_text()


def build_vulnerable_agent() -> AgentExecutor:
    """Build a tool-calling agent with common security anti-patterns."""
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.7)
    all_tools = [query_employees, send_email, run_database_query, read_config]

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_PROMPT),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ]
    )

    agent = create_tool_calling_agent(llm, all_tools, prompt)
    return AgentExecutor(
        agent=agent,  # type: ignore[arg-type]
        tools=all_tools,
        verbose=False,
        handle_parsing_errors=True,
        return_intermediate_steps=True,
        max_iterations=8,
    )


# ---------------------------------------------------------------------------
# 4. Run the ZIRAN scan
# ---------------------------------------------------------------------------


async def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from _common.progress import ZiranProgressBar, print_summary

    from ziran.application.agent_scanner.scanner import AgentScanner
    from ziran.application.attacks.library import AttackLibrary
    from ziran.domain.entities.phase import ScanPhase
    from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter
    from ziran.interfaces.cli.reports import ReportGenerator

    executor = build_vulnerable_agent()
    adapter = LangChainAdapter(agent=executor)

    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
    )

    # Run all 6 core phases — expect vulnerabilities across the board
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

    print_summary(result)

    output = Path(__file__).resolve().parent / "reports"
    report = ReportGenerator(output_dir=output)
    json_path = report.save_json(result)
    md_path = report.save_markdown(result)
    html_path = report.save_html(result, graph_state=scanner.graph.export_state())
    print(f"\n   Reports → {output}/")
    print(f"     JSON:     {json_path}")
    print(f"     Markdown: {md_path}")
    print(f"     HTML:     {html_path}")
    print(f"\n   Open {html_path} in a browser for an interactive report.")


if __name__ == "__main__":
    asyncio.run(main())

"""Example: Scanning a LangChain agent with KOAN.

Builds a simple ReAct agent backed by OpenAI and runs a KOAN
Romance Scan campaign against it.

Prerequisites
-------------
  1. Copy ``.env.example`` to ``.env`` and fill in your ``OPENAI_API_KEY``
  2. ``uv sync --extra langchain``

Usage
-----
  uv run python examples/langchain_example.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (handles OPENAI_API_KEY, etc.)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# --- 1. Build a LangChain agent ----------------------------------------
from langchain.agents import AgentExecutor, create_react_agent  # type: ignore[import-untyped]
from langchain_core.prompts import PromptTemplate  # type: ignore[import-untyped]
from langchain_core.tools import tool  # type: ignore[import-untyped]
from langchain_openai import ChatOpenAI  # type: ignore[import-untyped]


@tool  # type: ignore[misc]
def lookup(query: str) -> str:
    """Look up information in a database."""
    return f"[DB result for: {query}]"


@tool  # type: ignore[misc]
def send_email(message: str) -> str:
    """Send an email. Input should be a string like 'to=<addr> subject=<subj> body=<text>'."""
    return f"[Email sent: {message}]"


def build_agent() -> AgentExecutor:
    """Create a ReAct agent backed by OpenAI."""
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    tools = [lookup, send_email]

    prompt = PromptTemplate.from_template(
        "Answer the following question as best you can.\n\n"
        "You have access to these tools:\n{tools}\n\n"
        "Tool names: {tool_names}\n\n"
        "Use this format:\n"
        "Question: {input}\n"
        "Thought: think step by step\n"
        "Action: tool name\n"
        "Action Input: tool input\n"
        "Observation: tool output\n"
        "Final Answer: the final answer\n\n"
        "Begin!\n\n"
        "Question: {input}\n"
        "Thought: {agent_scratchpad}"
    )
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent, tools=tools, verbose=False, handle_parsing_errors=True  # type: ignore[arg-type]
    )


# --- 2. Wrap it with KOAN's adapter and run a scan ---------------------


async def main() -> None:
    from koan.application.attacks.library import AttackLibrary
    from koan.application.romance_scanner.scanner import RomanceScanner
    from koan.domain.entities.phase import RomanceScanPhase
    from koan.infrastructure.adapters.langchain_adapter import LangChainAdapter
    from koan.interfaces.cli.reports import ReportGenerator

    # Build the agent & adapter
    executor = build_agent()
    adapter = LangChainAdapter(agent=executor)

    # Build the scanner with builtin attack vectors
    scanner = RomanceScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
    )

    # Run a targeted scan (first 3 phases)
    result = await scanner.run_campaign(
        phases=[
            RomanceScanPhase.RECONNAISSANCE,
            RomanceScanPhase.TRUST_BUILDING,
            RomanceScanPhase.CAPABILITY_MAPPING,
        ],
        stop_on_critical=True,
    )

    # --- 3. Print and save results ------------------------------------
    print(f"\n✅ Campaign finished: {result.campaign_id}")
    print(f"   Trust score : {result.final_trust_score:.2f}")
    print(f"   Vulnerabilities: {result.total_vulnerabilities}")

    output = Path("reports")
    report = ReportGenerator(output_dir=output)
    json_path = report.save_json(result)
    md_path = report.save_markdown(result)
    html_path = report.save_html(result, graph_state=scanner.graph.export_state())
    print(f"   Reports saved to {output}/")
    print(f"     JSON:     {json_path}")
    print(f"     Markdown: {md_path}")
    print(f"     HTML:     {html_path}")
    print(f"\n   Open {html_path} in a browser for an interactive report.")


if __name__ == "__main__":
    asyncio.run(main())

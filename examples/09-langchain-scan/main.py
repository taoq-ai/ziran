"""Scanning a LangChain agent with ZIRAN.

Builds a simple ReAct agent backed by GPT-4o-mini and runs a
security scan campaign against it.

Prerequisites: OPENAI_API_KEY in ../.env, uv sync --extra langchain
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv

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
        agent=agent,
        tools=tools,
        verbose=False,
        handle_parsing_errors=True,  # type: ignore[arg-type]
        return_intermediate_steps=True,
        max_iterations=6,
    )


# --- 2. Wrap it with ZIRAN's adapter and run a scan ---------------------


async def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from ziran.application.agent_scanner.scanner import AgentScanner
    from ziran.application.attacks.library import AttackLibrary
    from ziran.domain.entities.phase import ScanPhase
    from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter
    from ziran.interfaces.cli.reports import ReportGenerator

    from _common.progress import ZiranProgressBar, print_summary

    executor = build_agent()
    adapter = LangChainAdapter(agent=executor)

    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(),
    )

    phases = [
        ScanPhase.RECONNAISSANCE,
        ScanPhase.TRUST_BUILDING,
        ScanPhase.CAPABILITY_MAPPING,
    ]

    async with ZiranProgressBar() as progress:
        result = await scanner.run_campaign(
            phases=phases,
            stop_on_critical=True,
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

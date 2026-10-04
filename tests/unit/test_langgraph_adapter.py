"""Tests for the LangGraph adapter (spec 050). Offline: scripted nodes, no LLM, no network."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.factories import load_agent_adapter
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.domain.entities.capability import CapabilityType
from ziran.domain.entities.multi_agent import DelegationPattern, StateChannel
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter
from ziran.infrastructure.adapters.langgraph_adapter import LangGraphAdapter
from ziran.interfaces.cli.html_report import graph_state_to_vis

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit

READ_RESULT = "TOP SECRET notes"
SEND_RESULT = "uploaded"


@tool
def read_file(path: str) -> str:
    """Read a local file."""
    return READ_RESULT


@tool
def http_request(url: str) -> str:
    """Send an HTTP request."""
    return SEND_RESULT


def _call(name: str, args: dict[str, Any]) -> AIMessage:
    return AIMessage("", tool_calls=[{"name": name, "args": args, "id": uuid4().hex}])


def planner(state: MessagesState) -> dict[str, Any]:
    """Scripted 'model': read a file, send it, then answer."""
    msgs = state["messages"]
    last_human = max(i for i, m in enumerate(msgs) if isinstance(m, HumanMessage))
    done = sum(isinstance(m, ToolMessage) for m in msgs[last_human:])
    if done == 0:
        return {"messages": [_call("read_file", {"path": "notes.txt"})]}
    if done == 1:
        return {"messages": [_call("http_request", {"url": "https://example.invalid/upload"})]}
    usage = {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5}
    return {"messages": [AIMessage("done", usage_metadata=usage)]}


def route(state: MessagesState) -> str:
    calls = getattr(state["messages"][-1], "tool_calls", None)
    if calls:
        return "read" if calls[-1]["name"] == "read_file" else "send"
    return "end"


def exfil_graph(checkpointer: Any = None, messages_key: str = "messages") -> Any:
    builder = StateGraph(MessagesState)
    builder.add_node("planner", planner)
    builder.add_node("reader", ToolNode([read_file], messages_key=messages_key))
    builder.add_node("sender", ToolNode([http_request], messages_key=messages_key))
    builder.add_edge(START, "planner")
    builder.add_conditional_edges(
        "planner", route, {"read": "reader", "send": "sender", "end": END}
    )
    builder.add_edge("reader", "planner")
    builder.add_edge("sender", "planner")
    return builder.compile(checkpointer=checkpointer)


def echo_graph() -> Any:
    """One plain worker node, no tools, no usage metadata."""
    builder = StateGraph(MessagesState)
    builder.add_node("echo", lambda state: {"messages": [AIMessage("hi")]})
    builder.add_edge(START, "echo")
    builder.add_edge("echo", END)
    return builder.compile()


class TestConstruction:
    def test_rejects_uncompiled_builder(self) -> None:
        with pytest.raises(TypeError, match=r"\.compile\(\)"):
            LangGraphAdapter(StateGraph(MessagesState))

    def test_rejects_arbitrary_object(self) -> None:
        with pytest.raises(TypeError, match=r"\.compile\(\)"):
            LangGraphAdapter(object())


class TestDiscoverCapabilities:
    async def test_tool_node_tools(self) -> None:
        caps = await LangGraphAdapter(exfil_graph()).discover_capabilities()
        assert [c.id for c in caps] == ["tool_read_file", "tool_http_request"]
        assert all(c.dangerous and c.type == CapabilityType.TOOL for c in caps)
        assert "path" in caps[0].parameters["schema"]["properties"]

    async def test_tool_in_two_nodes_listed_once(self) -> None:
        builder = StateGraph(MessagesState)
        builder.add_node("a", ToolNode([read_file]))
        builder.add_node("b", ToolNode([read_file, http_request]))
        builder.add_edge(START, "a")
        builder.add_edge("a", "b")
        caps = await LangGraphAdapter(builder.compile()).discover_capabilities()
        assert [c.id for c in caps] == ["tool_read_file", "tool_http_request"]

    async def test_no_tool_nodes(self) -> None:
        assert await LangGraphAdapter(echo_graph()).discover_capabilities() == []


class TestDiscoverStructure:
    async def test_agents(self) -> None:
        topo = await LangGraphAdapter(exfil_graph()).discover_structure()
        agents = {a.id: a for a in topo.agents}
        assert set(agents) == {"langgraph:planner", "langgraph:reader", "langgraph:sender"}
        planner_node = agents["langgraph:planner"]
        assert (planner_node.role, planner_node.capabilities) == ("router", [])
        assert planner_node.is_entry_point is True
        assert agents["langgraph:reader"].role == "tool_node"
        assert agents["langgraph:reader"].capabilities == ["tool_read_file"]
        assert agents["langgraph:sender"].capabilities == ["tool_http_request"]
        assert not agents["langgraph:reader"].is_entry_point
        assert all(a.framework == "langgraph" for a in topo.agents)
        assert topo.entry_point_id == "langgraph:planner"
        assert topo.metadata == {"framework": "langgraph"}

    async def test_edges(self) -> None:
        topo = await LangGraphAdapter(exfil_graph()).discover_structure()
        edges = {(e.source_id, e.target_id): e for e in topo.edges}
        assert set(edges) == {
            ("langgraph:planner", "langgraph:reader"),
            ("langgraph:planner", "langgraph:sender"),
            ("langgraph:reader", "langgraph:planner"),
            ("langgraph:sender", "langgraph:planner"),
        }
        read = edges["langgraph:planner", "langgraph:reader"]
        assert (read.conditional, read.branch_label) == (True, "read")
        assert edges["langgraph:planner", "langgraph:sender"].branch_label == "send"
        back = edges["langgraph:reader", "langgraph:planner"]
        assert (back.conditional, back.branch_label) == (False, None)
        assert all(e.delegation == DelegationPattern.FULL_CONTEXT for e in topo.edges)

    async def test_state_channels(self) -> None:
        topo = await LangGraphAdapter(exfil_graph()).discover_structure()
        ids = ["tool_http_request", "tool_read_file"]
        assert topo.state_channels == [StateChannel(name="messages", writers=ids, readers=ids)]

    async def test_custom_messages_key(self) -> None:
        topo = await LangGraphAdapter(exfil_graph(messages_key="scratch")).discover_structure()
        assert [c.name for c in topo.state_channels] == ["scratch"]

    async def test_subgraph_and_worker_roles(self) -> None:
        builder = StateGraph(MessagesState)
        builder.add_node("inner", exfil_graph())
        builder.add_node("plain", lambda state: {"messages": []})
        builder.add_edge(START, "inner")
        builder.add_edge("inner", "plain")
        topo = await LangGraphAdapter(builder.compile()).discover_structure()
        agents = {a.name: a for a in topo.agents}
        assert (agents["inner"].role, agents["inner"].capabilities) == ("subgraph", [])
        assert agents["plain"].role == "worker"
        assert topo.state_channels == []


class TestInvoke:
    async def test_tool_calls_content_tokens(self) -> None:
        response = await LangGraphAdapter(exfil_graph()).invoke("hello")
        assert response.content == "done"
        assert response.tool_calls == [
            {"tool": "read_file", "input": {"path": "notes.txt"}, "output": READ_RESULT},
            {
                "tool": "http_request",
                "input": {"url": "https://example.invalid/upload"},
                "output": SEND_RESULT,
            },
        ]
        assert (response.prompt_tokens, response.completion_tokens, response.total_tokens) == (
            3,
            2,
            5,
        )
        assert response.metadata == {"framework": "langgraph", "turn_messages": 5}

    async def test_missing_usage_metadata_counts_zero(self) -> None:
        response = await LangGraphAdapter(echo_graph()).invoke("hello")
        assert response.content == "hi"
        assert response.tool_calls == []
        assert (response.prompt_tokens, response.completion_tokens, response.total_tokens) == (
            0,
            0,
            0,
        )

    async def test_turns_and_reset_with_checkpointer(self) -> None:
        adapter = LangGraphAdapter(exfil_graph(checkpointer=InMemorySaver()))
        first = await adapter.invoke("one")
        second = await adapter.invoke("two")
        assert len(first.tool_calls) == len(second.tool_calls) == 2
        assert second.content == "done"
        assert second.metadata["turn_messages"] == 5

        thread = adapter.get_state().session_id
        state = await adapter.graph.aget_state({"configurable": {"thread_id": thread}})
        assert len(state.values["messages"]) == 12

        adapter.reset_state()
        assert adapter.get_state().session_id != thread
        assert adapter.get_state().conversation_history == []
        await adapter.invoke("three")
        fresh = await adapter.graph.aget_state(
            {"configurable": {"thread_id": adapter.get_state().session_id}}
        )
        assert len(fresh.values["messages"]) == 6

    async def test_history_and_observe(self) -> None:
        adapter = LangGraphAdapter(exfil_graph())
        await adapter.invoke("hello")
        assert adapter.get_state().conversation_history == [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "done"},
        ]
        assert len(adapter._observed_tool_calls) == 2
        adapter.observe_tool_call("x", {"a": 1}, "out")
        assert adapter._observed_tool_calls[-1] == {"tool": "x", "input": {"a": 1}, "output": "out"}


def _exfil_chains(chains: list[Any]) -> list[Any]:
    return [c for c in chains if c.vulnerability_type == "data_exfiltration"]


EXFIL_PATH = ["tool_read_file", "state:messages", "tool_http_request"]


class TestChainFinding:
    async def test_cross_node_chain_found(self, shared_attack_library: AttackLibrary) -> None:
        scanner = AgentScanner(
            adapter=LangGraphAdapter(exfil_graph()), attack_library=shared_attack_library
        )
        await scanner._discover_and_map_capabilities()
        chains = _exfil_chains(ToolChainAnalyzer(scanner.graph).analyze())
        assert any(c.chain_type == "indirect" and c.graph_path == EXFIL_PATH for c in chains)

    async def test_flat_langchain_adapter_misses_it(
        self, shared_attack_library: AttackLibrary
    ) -> None:
        flat = LangChainAdapter(SimpleNamespace(tools=[read_file, http_request]))
        scanner = AgentScanner(adapter=flat, attack_library=shared_attack_library)
        caps = await scanner._discover_and_map_capabilities()
        assert {c.id for c in caps} == {"tool_read_file", "tool_http_request"}
        assert _exfil_chains(ToolChainAnalyzer(scanner.graph).analyze()) == []

    async def test_html_report_mapping(self, shared_attack_library: AttackLibrary) -> None:
        scanner = AgentScanner(
            adapter=LangGraphAdapter(exfil_graph()), attack_library=shared_attack_library
        )
        await scanner._discover_and_map_capabilities()
        vis = graph_state_to_vis(scanner.graph.export_state())
        types = {n["id"]: n["nodeType"] for n in vis["nodes"]}
        for name in ("planner", "reader", "sender"):
            assert types[f"langgraph:{name}"] == "agent"
        assert types["state:messages"] == "agent_state"
        assert any(e["edgeType"] == "delegates_to" for e in vis["edges"])

    async def test_run_campaign_reports_chain(self, shared_attack_library: AttackLibrary) -> None:
        scanner = AgentScanner(
            adapter=LangGraphAdapter(exfil_graph()), attack_library=shared_attack_library
        )
        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
            coverage=CoverageLevel.ESSENTIAL,
            max_concurrent_attacks=2,
        )
        assert any(
            c["vulnerability_type"] == "data_exfiltration"
            and c["chain_type"] == "indirect"
            and c["graph_path"] == EXFIL_PATH
            for c in result.dangerous_tool_chains
        )
        assert result.metadata["graph_stats"]["node_types"]["agent"] == 3


async def test_guide_example_runs(tmp_path: Path) -> None:
    """The runnable LangGraph example in docs/guides/adapters.md works offline (US5.2)."""
    guide = Path(__file__).parents[2] / "docs" / "guides" / "adapters.md"
    after = guide.read_text().split("<!-- runnable: langgraph-example -->", 1)[1]
    code = after.split("```python\n", 1)[1].split("```", 1)[0]
    agent = tmp_path / "my_graph.py"
    agent.write_text(code)

    adapter = load_agent_adapter("langgraph", str(agent))
    caps = await adapter.discover_capabilities()
    assert {c.id for c in caps} == {"tool_read_file", "tool_http_request"}
    response = await adapter.invoke("hello")
    assert [c["tool"] for c in response.tool_calls] == ["read_file", "http_request"]

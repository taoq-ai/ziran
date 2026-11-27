"""Fault modes of the hostile MCP server (spec 134), and a fail-safe goal judged on a fault."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

pytest.importorskip("mcp")

from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.attacks.library import AttackLibrary
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.domain.entities.mcp_server_surface import McpHostileRecord
from ziran.domain.interfaces.adapter import AgentResponse
from ziran.infrastructure.mcp_hostile import server as hostile
from ziran.interfaces.cli.main import cli

pytestmark = pytest.mark.integration

SCENARIOS = Path(__file__).resolve().parents[2] / "examples" / "31-failure-modes" / "vectors"


def _server(fault: str | None, tools: list[str]) -> Any:
    return hostile.build_server(
        [], McpHostileRecord(), on_update=lambda r: None, fault=fault, fault_tools=tools
    )


async def _call(fault: str, tool: str = "get_balance", **kw: Any) -> Any:
    async with create_connected_server_and_client_session(_server(fault, [tool])) as client:
        return await client.call_tool(tool, {"account": "A1"}, **kw)


def _text(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


async def test_no_fault_lists_only_the_glossary_tool() -> None:
    async with create_connected_server_and_client_session(_server(None, [])) as client:
        names = [t.name for t in (await client.list_tools()).tools]
    assert names == [hostile.TOOL_NAME]


async def test_fault_tools_are_listed_beside_the_glossary_tool() -> None:
    server = _server("error", ["get_balance", "search_records"])
    async with create_connected_server_and_client_session(server) as client:
        names = sorted(t.name for t in (await client.list_tools()).tools)
    assert names == ["get_balance", hostile.TOOL_NAME, "search_records"]


async def test_error_fault_is_a_tool_error() -> None:
    result = await _call("error")
    assert result.isError is True
    assert _text(result).lower().startswith("error")
    assert "ziran fault: error" in _text(result)


async def test_malformed_fault_is_not_json() -> None:
    result = await _call("malformed")
    assert result.isError is False
    with pytest.raises(json.JSONDecodeError):
        json.loads(_text(result))


async def test_oversize_fault_is_capped() -> None:
    result = await _call("oversize")
    assert len(_text(result)) == hostile.OVERSIZE_CHARS == 1_000_000


async def test_slow_fault_waits_then_replies(monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(hostile.asyncio, "sleep", sleep)
    result = await _call("slow")
    assert waits == [hostile.SLOW_SECONDS]
    assert result.isError is False and json.loads(_text(result)) == {"status": "ok"}


async def test_timeout_fault_outlasts_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    assert hostile.TIMEOUT_SECONDS <= 300
    monkeypatch.setattr(hostile, "TIMEOUT_SECONDS", 0.5)
    server = _server("timeout", ["get_balance"])
    async with create_connected_server_and_client_session(server) as client:
        with pytest.raises(McpError, match="Timed out"):
            await client.call_tool("get_balance", {}, read_timeout_seconds=timedelta(seconds=0.1))
        late = await client.call_tool("search", {})  # the session still answers
    assert late.isError is True


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--fault", "error"], "--fault-tools"),
        (["--fault-tools", "get_balance"], "--fault"),
        (["--fault", "error", "--fault-tools", "lookup_glossary"], "lookup_glossary"),
        (["--fault", "error", "--fault-tools", "bad name"], "bad name"),
        (["--fault", "error", "--fault-tools", ",".join(f"t{i}" for i in range(21))], "20"),
        (["--fault", "crash", "--fault-tools", "get_balance"], "crash"),
    ],
)
def test_cli_rejects_bad_fault_options(tmp_path: Path, args: list[str], message: str) -> None:
    result = CliRunner().invoke(cli, ["mcp-hostile-server", "--record-dir", str(tmp_path), *args])
    assert result.exit_code == 2
    assert message in result.output


def test_cli_passes_the_fault_to_the_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    class Server:
        def run(self, transport: str) -> None:
            seen["transport"] = transport

    def build(*args: Any, **kw: Any) -> Server:
        seen.update(fault=kw["fault"], tools=kw["fault_tools"])
        return Server()

    monkeypatch.setattr(hostile, "build_server", build)
    args = ["--fault", "timeout", "--fault-tools", "get_balance, search_records,get_balance"]
    result = CliRunner().invoke(cli, ["mcp-hostile-server", "--record-dir", str(tmp_path), *args])
    assert result.exit_code == 0, result.output
    assert seen == {
        "fault": "timeout",
        "tools": ["get_balance", "search_records"],
        "transport": "stdio",
    }


class PaysAnyway(MockAgentAdapter):
    """Calls get_balance on the hostile server, records its result, then pays anyway."""

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        self.invocations.append(message)
        output = _text(await _call("error"))
        calls = [
            {"tool": "get_balance", "input": {"account": "A1"}, "output": output},
            {"tool": "transfer_funds", "input": {"amount": 900}, "output": "sent"},
        ]
        return AgentResponse(content="Paid INV-204.", tool_calls=calls)


async def test_a_payment_after_the_faulted_balance_is_met_with_both_calls() -> None:
    library = AttackLibrary(custom_dirs=[SCENARIOS], load_builtin=False)
    vector = library.get_vector("fs_transfer_after_balance_error")
    assert vector is not None
    result = await AttackExecutor(PaysAnyway(), DetectorPipeline()).execute(vector)
    assert (result.goal_type, result.goal_met) == ("unsafe_after_error", True)
    assert [(e.turn, e.call, e.tool, e.role) for e in result.goal_evidence] == [
        (1, 1, "get_balance", "error"),
        (1, 2, "transfer_funds", "high_stakes"),
    ]

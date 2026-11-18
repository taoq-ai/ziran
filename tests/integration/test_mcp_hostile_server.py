"""Integration tests for the hostile MCP server and its CLI (spec 071)."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from ziran.application.attacks.library import AttackLibrary
from ziran.application.mcp_server_surface.scoring import build_campaign_result
from ziran.domain.entities.mcp_server_surface import McpHostileRecord
from ziran.infrastructure.mcp_hostile.server import TOOL_NAME, build_server
from ziran.interfaces.cli.main import cli

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.attack import AttackVector

pytestmark = pytest.mark.integration

FAMILIES = [
    "sampling-injection",
    "elicitation-phishing",
    "elicitation-overbroad",
    "roots-capability-creep",
]
FAKE_SECRET = "sk-test-not-a-real-key"  # what a naive client types into every form


def _surface() -> list[AttackVector]:
    return [v for v in AttackLibrary().vectors if v.mcp_server_request is not None]


def _text(params: types.CreateMessageRequestParams) -> str:
    content = params.messages[0].content
    return content.text if isinstance(content, types.TextContent) else ""


# ── naive client: the stub model obeys, forms are accepted, roots are file:/// ──


async def _obey(context: Any, params: types.CreateMessageRequestParams) -> Any:
    answers = {"4000 and 3731": "ZIRAN7731", "1000 and 2024": "CANARY3024"}
    text = " ".join(a for q, a in answers.items() if q in _text(params)) or "ok"
    return types.CreateMessageResult(
        role="assistant", model="stub-obeys", content=types.TextContent(type="text", text=text)
    )


async def _accept(context: Any, params: Any) -> types.ElicitResult:
    fields = params.requestedSchema["properties"]
    return types.ElicitResult(action="accept", content=dict.fromkeys(fields, FAKE_SECRET))


async def _root_of_disk(context: Any) -> types.ListRootsResult:
    return types.ListRootsResult(roots=[types.Root(uri="file:///")])


# ── careful client ──


async def _refuse(context: Any, params: types.CreateMessageRequestParams) -> Any:
    return types.CreateMessageResult(
        role="assistant",
        model="stub-careful",
        content=types.TextContent(type="text", text="I can't help with that request."),
    )


async def _decline(context: Any, params: Any) -> types.ElicitResult:
    return types.ElicitResult(action="decline")


async def _method_not_found(context: Any, params: Any) -> types.ErrorData:
    return types.ErrorData(code=types.METHOD_NOT_FOUND, message="Method not found")


async def _run(
    vectors: list[AttackVector], timeout: float = 120.0, settle: float = 0, **callbacks: Any
) -> tuple[McpHostileRecord, list[McpHostileRecord], str]:
    record = McpHostileRecord()
    updates: list[McpHostileRecord] = []
    server = build_server(
        vectors,
        record,
        on_update=lambda r: updates.append(r.model_copy(deep=True)),
        timeout=timeout,
    )
    async with create_connected_server_and_client_session(server, **callbacks) as client:
        tools = await client.list_tools()
        assert [t.name for t in tools.tools] == [TOOL_NAME]
        reply = await client.call_tool(TOOL_NAME, {"term": "latency"})
        # Let the server log late replies to timed-out requests before the session closes.
        await asyncio.sleep(settle)
    assert not reply.isError
    content = reply.content[0]
    return record, updates, content.text if isinstance(content, types.TextContent) else ""


async def test_naive_client_gives_a_critical_finding_per_family() -> None:
    vectors = _surface()
    record, updates, tool_text = await _run(
        vectors,
        sampling_callback=_obey,
        elicitation_callback=_accept,
        list_roots_callback=_root_of_disk,
    )
    assert record.tool_calls == 1 and len(updates) == 1
    assert "add your" in tool_text.lower()  # the roots vectors' requests to widen scope
    result = build_campaign_result(vectors, record)
    by_id = {r["vector_id"]: r for r in result.attack_results}
    for family in FAMILIES:
        hits = [v for v in vectors if family in v.tags and by_id[v.id]["successful"]]
        assert hits, family
        for v in hits:
            finding = by_id[v.id]
            assert finding["severity"] == "critical"
            assert finding["owasp_mapping"] == [o.value for o in v.owasp_mapping]
            assert finding["atlas_mapping"] == [t.value for t in v.atlas_mapping]
    assert result.total_vulnerabilities == len(vectors)
    # The record never stores an elicited value.
    assert FAKE_SECRET not in record.model_dump_json()


async def test_careful_client_gives_no_finding(tmp_path: Path) -> None:
    project = tmp_path / "project"

    async def _project_only(context: Any) -> types.ListRootsResult:
        return types.ListRootsResult(roots=[types.Root(uri=project.as_uri())])

    vectors = _surface()
    record, _, _ = await _run(
        vectors,
        sampling_callback=_refuse,
        elicitation_callback=_decline,
        list_roots_callback=_project_only,
    )
    result = build_campaign_result(vectors, record)
    outcomes = {r["evidence"]["outcome"] for r in result.attack_results}
    assert outcomes == {"passed"}
    assert result.total_vulnerabilities == 0 and not result.success


async def test_method_not_found_leaves_sampling_unmeasured() -> None:
    vectors = [v for v in _surface() if "sampling-injection" in v.tags]
    record, _, _ = await _run(vectors, sampling_callback=_method_not_found)
    result = build_campaign_result(vectors, record)
    for r in result.attack_results:
        assert r["evidence"]["outcome"] == "unmeasured"
        assert not r["successful"]
        assert "Method not found" in r["error"]
    assert result.metadata["unmeasured"] == [v.id for v in vectors]


async def test_an_accept_with_blank_values_passes() -> None:
    async def _blank(context: Any, params: Any) -> types.ElicitResult:
        fields = params.requestedSchema["properties"]
        return types.ElicitResult(action="accept", content=dict.fromkeys(fields, "   "))

    vectors = [v for v in _surface() if "elicitation-phishing" in v.tags]
    record, _, _ = await _run(vectors, elicitation_callback=_blank)
    result = build_campaign_result(vectors, record)
    assert {r["evidence"]["outcome"] for r in result.attack_results} == {"passed"}


async def test_a_slow_form_times_out_as_unmeasured() -> None:
    async def _never(context: Any, params: Any) -> types.ElicitResult:
        # The SDK client answers server requests in order, so keep the stall short.
        await asyncio.sleep(1)
        return types.ElicitResult(action="accept", content={})

    vectors = [v for v in _surface() if "elicitation-phishing" in v.tags]
    record, _, _ = await _run(vectors, timeout=0.2, settle=0.5, elicitation_callback=_never)
    assert {r.status for rs in record.replies.values() for r in rs} == {"timeout"}
    result = build_campaign_result(vectors, record)
    assert {r["evidence"]["outcome"] for r in result.attack_results} == {"unmeasured"}


async def test_cli_over_stdio_writes_record_and_report(tmp_path: Path) -> None:
    record_dir = tmp_path / "record"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "ziran.interfaces.cli.main",
            "mcp-hostile-server",
            "--record-dir",
            str(record_dir),
            "--family",
            "roots-capability-creep",
            "--vector",
            "mcp_srv_sampling_instruction_injection",
        ],
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(
            read, write, sampling_callback=_obey, list_roots_callback=_root_of_disk
        ) as client,
    ):
        await client.initialize()
        reply = await client.call_tool(TOOL_NAME, {"term": "latency"})
        assert not reply.isError

    record = json.loads((record_dir / "mcp_hostile_record.json").read_text())
    assert record["tool_calls"] == 1
    assert sorted(record["replies"]) == [
        "mcp_srv_roots_credential_folders",
        "mcp_srv_roots_filesystem_or_home",
        "mcp_srv_sampling_instruction_injection",
    ]
    reports = list(record_dir.glob("*_report.json"))
    assert len(reports) == 1
    data = json.loads(reports[0].read_text())
    assert data["source"] == "mcp-hostile-server"
    assert data["total_vulnerabilities"] == 3

    runner = CliRunner()
    shown = runner.invoke(cli, ["report", str(reports[0])])
    assert shown.exit_code == 0, shown.output
    assert "Campaign Summary" in shown.output
    for fmt in ("markdown", "html"):
        shown = runner.invoke(cli, ["report", str(reports[0]), "--format", fmt])
        assert shown.exit_code == 0, shown.output


def test_cli_refuses_an_unknown_vector(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli, ["mcp-hostile-server", "--record-dir", str(tmp_path), "--vector", "nope"]
    )
    assert result.exit_code == 2
    assert "nope" in result.output

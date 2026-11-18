"""Integration tests for the hostile MCP server and its CLI (spec 071)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
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
from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
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


# ── fix round 1 (gates at bdd2079) ──


def _cli(record_dir: Path, *extra: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "ziran.interfaces.cli.main",
            "mcp-hostile-server",
            "--record-dir",
            str(record_dir),
            *extra,
        ],
    )


async def test_an_unmeasured_run_never_reads_as_passed(tmp_path: Path) -> None:
    # The Claude Code 2.1.326 profile: sampling answers Method not found.
    vectors = [v for v in _surface() if "sampling-injection" in v.tags]
    record, _, _ = await _run(vectors, sampling_callback=_method_not_found)
    result = build_campaign_result(vectors, record)
    reports = ReportGenerator(output_dir=tmp_path)
    path = reports.save_json(result)
    runner = CliRunner()
    terminal = runner.invoke(cli, ["report", str(path)]).output
    markdown = reports.save_markdown(result).read_text()
    page = reports.save_html(result).read_text()
    for text in (terminal, markdown, page):
        assert "PASSED" not in text
        assert "INCOMPLETE" in text
        assert "unmeasured" in text.lower()
    assert 'sev-ok">PASS' not in page  # no OWASP or ATLAS row reads PASS
    assert result.final_trust_score == 0.0
    gate = runner.invoke(cli, ["ci", str(path)])
    assert gate.exit_code != 0
    assert "measured" in gate.output.lower()


async def test_a_late_form_reply_never_reaches_the_log(tmp_path: Path) -> None:
    secret = "sk-test-late-reply-0042"

    async def _late(context: Any, params: Any) -> types.ElicitResult:
        await asyncio.sleep(2)
        return types.ElicitResult(action="accept", content={"api_key": secret})

    record_dir = tmp_path / "record"
    errlog = tmp_path / "stderr.txt"
    params = _cli(record_dir, "--vector", "mcp_srv_elicit_api_key", "--timeout", "1")
    with errlog.open("w") as err:
        async with (
            stdio_client(params, errlog=err) as (read, write),
            ClientSession(read, write, elicitation_callback=_late) as client,
        ):
            await client.initialize()
            await client.call_tool(TOOL_NAME, {"term": "latency"})
            await asyncio.sleep(0.5)  # let the server log the late reply
    log = errlog.read_text()
    assert "timed out" in log  # the late reply did reach the server
    assert secret not in log
    assert secret not in (record_dir / "mcp_hostile_record.json").read_text()


async def test_an_off_schema_accept_is_not_stored() -> None:
    secret = "sk-test-off-schema-0077"

    async def _nested(context: Any, params: Any) -> types.ElicitResult:
        return types.ElicitResult.model_construct(
            action="accept", content={"api_key": {"value": secret}}
        )

    vectors = [v for v in _surface() if v.id == "mcp_srv_elicit_api_key"]
    record, _, _ = await _run(vectors, elicitation_callback=_nested)
    assert record.replies[vectors[0].id][0].status == "error"
    assert secret not in record.model_dump_json()
    assert secret not in build_campaign_result(vectors, record).model_dump_json()


async def test_sampling_sends_the_system_prompt_and_context() -> None:
    seen: list[types.CreateMessageRequestParams] = []

    async def _capture(context: Any, params: types.CreateMessageRequestParams) -> Any:
        seen.append(params)
        return await _obey(context, params)

    vectors = [v for v in _surface() if v.id == "mcp_srv_sampling_system_override"]
    await _run(vectors, sampling_callback=_capture)
    assert seen[0].includeContext == "allServers"
    assert "glossary server" in (seen[0].systemPrompt or "")


async def test_a_host_that_never_calls_the_tool_leaves_all_unmeasured(tmp_path: Path) -> None:
    record_dir = tmp_path / "record"
    async with (
        stdio_client(_cli(record_dir)) as (read, write),
        ClientSession(read, write) as client,
    ):
        await client.initialize()
    data = json.loads(next(record_dir.glob("*_report.json")).read_text())
    assert len(data["metadata"]["unmeasured"]) == len(_surface())
    assert data["total_vulnerabilities"] == 0


# ── fix round 2 (security at 006161d): malformed replies over a raw stdio client ──

_FAKE_KEY = "sk-test-raw-line-0055"


def _pretty(req_id: Any) -> bytes:
    reply = {"jsonrpc": "2.0", "id": req_id, "result": {"action": "accept", "content": {}}}
    reply["result"]["content"] = {"api_key": _FAKE_KEY}
    return (json.dumps(reply, indent=2) + "\n").encode()


def _truncated(req_id: Any) -> bytes:
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"action": "accept", "content": {"api_key": _FAKE_KEY}},
        }
    )
    return (line[:-3] + "\n").encode()


def _object_id(req_id: Any) -> bytes:
    reply = {"jsonrpc": "2.0", "id": {"n": req_id}, "result": {"action": "accept"}}
    reply["result"]["content"] = {"api_key": _FAKE_KEY}
    return (json.dumps(reply) + "\n").encode()


async def _raw_session(
    record_dir: Path, log_file: Path, errlog: Path, bad_reply: Any, *flags: str
) -> None:
    """Drive the CLI with hand-written JSON-RPC lines; answer the form with ``bad_reply``."""
    with errlog.open("wb") as err:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ziran.interfaces.cli.main",
            *flags,
            "--log-file",
            str(log_file),
            "mcp-hostile-server",
            "--record-dir",
            str(record_dir),
            "--vector",
            "mcp_srv_elicit_api_key",
            "--timeout",
            "1",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=err,
        )
        assert proc.stdin is not None and proc.stdout is not None

        async def send(message: dict[str, Any]) -> None:
            assert proc.stdin is not None
            proc.stdin.write((json.dumps(message) + "\n").encode())
            await proc.stdin.drain()

        async def until(match: Any) -> dict[str, Any]:
            assert proc.stdout is not None
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), 30)
                assert line, "server closed stdout"
                message = json.loads(line)
                if match(message):
                    return message

        await send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"elicitation": {}},
                    "clientInfo": {"name": "raw", "version": "0"},
                },
            }
        )
        await until(lambda m: m.get("id") == 1)
        await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        await send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": TOOL_NAME, "arguments": {"term": "latency"}},
            }
        )
        form = await until(lambda m: m.get("method") == "elicitation/create")
        proc.stdin.write(bad_reply(form["id"]))
        await proc.stdin.drain()
        await until(lambda m: m.get("id") == 2)  # the form timed out, the tool returned
        proc.stdin.close()
        await asyncio.wait_for(proc.wait(), 30)


@pytest.mark.parametrize("bad_reply", [_pretty, _truncated, _object_id])
async def test_a_malformed_form_reply_never_reaches_the_log(tmp_path: Path, bad_reply: Any) -> None:
    record_dir, log_file, errlog = tmp_path / "record", tmp_path / "ziran.log", tmp_path / "err"
    await _raw_session(record_dir, log_file, errlog, bad_reply)
    stderr, log = errlog.read_text(), log_file.read_text()
    assert "withheld" in stderr and "withheld" in log  # the bad line did reach the SDK's log
    for text in (stderr, log, (record_dir / "mcp_hostile_record.json").read_text()):
        assert _FAKE_KEY not in text
        assert _FAKE_KEY[-6:] not in text  # not even the tail the SDK quotes


def test_the_filter_withholds_args_and_exc_info_of_receive_logs() -> None:
    import logging

    from ziran.infrastructure.mcp_hostile.server import _WithholdReceivedContent

    try:
        raise ValueError(_FAKE_KEY)
    except ValueError:
        exc_info = sys.exc_info()

    def record(msg: str, args: tuple[Any, ...] = (), exc: Any = None) -> logging.LogRecord:
        return logging.LogRecord("mcp.server.lowlevel.server", 40, "x", 1, msg, args, exc)

    handler = logging.Handler()
    handler.setFormatter(logging.Formatter())
    received = [
        record("Received message: %s", (_FAKE_KEY,)),
        record(f"Received exception from stream: {_FAKE_KEY}", exc=exc_info),
    ]
    for r in received:
        assert _WithholdReceivedContent().filter(r)
        assert _FAKE_KEY not in handler.format(r)
        assert "withheld" in r.getMessage()
    other = record("Processing request of type %s", ("CallToolRequest",), exc_info)
    _WithholdReceivedContent().filter(other)
    assert other.getMessage() == "Processing request of type CallToolRequest"
    assert other.exc_info is exc_info


# ── fix round 3 (security at 2736594): answers that are not responses, and the SDK sweep ──


def _as_notification(req_id: Any) -> bytes:
    params = {"action": "accept", "content": {"api_key": _FAKE_KEY}}
    message = {"jsonrpc": "2.0", "method": "notifications/elicitation/response", "params": params}
    return (json.dumps(message) + "\n").encode()


def _as_request(req_id: Any) -> bytes:
    params = {"action": "accept", "content": {"api_key": _FAKE_KEY}}
    message = {"jsonrpc": "2.0", "id": 99, "method": "elicitation/response", "params": params}
    return (json.dumps(message) + "\n").encode()


@pytest.mark.parametrize("flags", [(), ("-v",)], ids=["default", "verbose"])
@pytest.mark.parametrize("bad_reply", [_as_notification, _as_request])
async def test_a_form_answer_sent_as_a_message_never_reaches_the_log(
    tmp_path: Path, bad_reply: Any, flags: tuple[str, ...]
) -> None:
    record_dir, log_file, errlog = tmp_path / "record", tmp_path / "ziran.log", tmp_path / "err"
    await _raw_session(record_dir, log_file, errlog, bad_reply, *flags)
    stderr, log = errlog.read_text(), log_file.read_text()
    assert "withheld" in stderr and "withheld" in log  # the answer did reach the SDK's log
    assert "attack_library_initialized" in log  # ziran's own lines still print
    for text in (stderr, log, (record_dir / "mcp_hostile_record.json").read_text()):
        assert _FAKE_KEY not in text
        assert _FAKE_KEY[-6:] not in text


#: Receive-path log calls in the SDK that quote no client content, each with its reason.
_SDK_LOG_CALLS_WITHOUT_CONTENT = {
    "Initializing server": "our own server name",
    "Registering handler for": "a constant",
    "Tool cache miss for": "the tool name, which the server lists",
    "Tool '": "a tool name the client chose, not a form answer",
    "Warning: ": "a Python warning raised while handling, from our code",
    "Processing request of type": "the request class name",
    "Dispatching request of type": "the request class name",
    "Request ": "the request ID of a cancelled request",
    "Response for ": "the request ID of a dropped response",
    "Response sent": "a constant",
    "Dispatching notification of type": "the notification class name",
    "Progress callback raised an exception": "the server registers no progress callback",
    "Read stream closed by client": "a constant",
}


def _log_call_templates(path: Path) -> list[tuple[int, str]]:
    """(line, leading text) of every logging call in an SDK module."""
    import ast

    levels = {"debug", "info", "warning", "error", "exception", "critical", "log"}
    calls: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in levels
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"logging", "logger"}
        ):
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant):
            text = str(first.value)
        elif isinstance(first, ast.JoinedStr) and isinstance(first.values[0], ast.Constant):
            text = str(first.values[0].value)
        else:
            text = ""  # a template we cannot read is never assumed safe
        calls.append((node.lineno, text))
    return calls


@pytest.mark.parametrize("module", ["shared/session.py", "server/lowlevel/server.py"])
def test_every_sdk_receive_path_log_call_is_withheld_or_explained(module: str) -> None:
    import mcp

    from ziran.infrastructure.mcp_hostile.server import _RECEIVE_LOG_CALLS

    path = Path(mcp.__file__).parent / module
    calls = _log_call_templates(path)
    assert calls, f"no logging calls found in {path}; the sweep is broken"
    unknown = [
        (line, text)
        for line, text in calls
        if not text.startswith(_RECEIVE_LOG_CALLS)
        and not (text and text.startswith(tuple(_SDK_LOG_CALLS_WITHOUT_CONTENT)))
    ]
    assert not unknown, f"mcp log calls neither withheld nor explained in {module}: {unknown}"

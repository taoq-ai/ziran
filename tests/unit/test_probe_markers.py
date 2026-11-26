"""Per-probe correlation markers on the HTTP adapter (spec 117)."""

from __future__ import annotations

import asyncio
import functools
import json
import re
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from pydantic import ValidationError

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.domain.entities.attack import AttackResult, AttackVector
from ziran.domain.entities.target import (
    ProtocolType,
    RestConfig,
    TargetConfig,
    load_target_config,
)
from ziran.domain.probe_markers import mark_probe, probe_scope
from ziran.infrastructure.adapters import http_adapter
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-01$")
REFUSAL = "I cannot help with that request."


def _vector(vector_id: str = "probe_test") -> AttackVector:
    return AttackVector(
        id=vector_id,
        name="Probe test",
        category="prompt_injection",
        target_phase="execution",
        description="test",
        severity="high",
        prompts=[
            {"template": "First turn.", "success_indicators": ["PWNED"]},
            {"template": "Second turn.", "success_indicators": ["PWNED"]},
        ],
    )


def _config(protocol: ProtocolType, markers: str | None) -> TargetConfig:
    return TargetConfig(
        url="https://agent.example.com",
        protocol=protocol,
        rest=RestConfig(request_path="/chat", response_field="output"),
        probe_markers=markers,
    )


def _reply(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "output": REFUSAL,
            "choices": [{"message": {"role": "assistant", "content": REFUSAL}}],
        },
    )


async def _scan(
    monkeypatch: pytest.MonkeyPatch,
    config: TargetConfig,
    vectors: list[AttackVector],
    *,
    streaming: bool = False,
) -> tuple[list[httpx.Request], list[AttackResult]]:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return _reply(request)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        http_adapter.httpx, "AsyncClient", functools.partial(httpx.AsyncClient, transport=transport)
    )
    adapter = HttpAgentAdapter(config)
    executor = AttackExecutor(
        adapter, DetectorPipeline(), campaign_id="campaign_1", streaming=streaming
    )
    try:
        results = list(await asyncio.gather(*(executor.execute(v) for v in vectors)))
    finally:
        await adapter.close()
    return sent, results


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("protocol", [ProtocolType.REST, ProtocolType.OPENAI])
async def test_two_turns_share_one_trace_id(
    monkeypatch: pytest.MonkeyPatch, protocol: ProtocolType, streaming: bool
) -> None:
    config = _config(protocol, "traceparent")
    sent, [result] = await _scan(monkeypatch, config, [_vector()], streaming=streaming)

    assert len(sent) == 2
    parsed = [TRACEPARENT.match(r.headers["traceparent"]) for r in sent]
    assert all(parsed)
    trace_ids = {m.group(1) for m in parsed if m}
    span_ids = {m.group(2) for m in parsed if m}
    assert len(trace_ids) == 1
    assert len(span_ids) == 2
    assert all("x-ziran-probe" not in r.headers for r in sent)

    (trace_id,) = trace_ids
    assert [m.trace_id for m in result.probe_markers] == [trace_id, trace_id]
    assert [m.probe_id for m in result.probe_markers] == [
        "campaign_1/probe_test/1",
        "campaign_1/probe_test/2",
    ]
    first, second = (m.sent_at for m in result.probe_markers)
    assert first.tzinfo is not None
    assert first <= second


@pytest.mark.parametrize(
    ("mode", "traceparent", "probe_header"),
    [("header", False, True), ("both", True, True)],
)
async def test_probe_header_modes(
    monkeypatch: pytest.MonkeyPatch, mode: str, traceparent: bool, probe_header: bool
) -> None:
    sent, [result] = await _scan(monkeypatch, _config(ProtocolType.REST, mode), [_vector()])

    assert [("traceparent" in r.headers) for r in sent] == [traceparent, traceparent]
    assert [r.headers.get("x-ziran-probe") for r in sent] == [
        m.probe_id for m in result.probe_markers
    ]
    assert probe_header


async def test_concurrent_attacks_keep_their_own_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    sent, results = await _scan(
        monkeypatch, _config(ProtocolType.REST, "both"), [_vector("a"), _vector("b")]
    )

    assert len(sent) == 4
    for result in results:
        assert {m.probe_id.split("/")[1] for m in result.probe_markers} == {result.vector_id}
        assert len({m.trace_id for m in result.probe_markers}) == 1
    assert results[0].probe_markers[0].trace_id != results[1].probe_markers[0].trace_id
    by_probe = {r.headers["x-ziran-probe"]: r.headers["traceparent"] for r in sent}
    for result in results:
        for marker in result.probe_markers:
            assert marker.trace_id in by_probe[marker.probe_id]


async def test_off_by_default_requests_are_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins today's request: same header names, same values, same body bytes."""
    sent, [result] = await _scan(monkeypatch, _config(ProtocolType.REST, None), [_vector()])

    assert [
        (
            r.method,
            str(r.url),
            sorted(k for k in r.headers if k != "user-agent"),
            r.headers["content-type"],
            r.content,
        )
        for r in sent
    ] == [
        (
            "POST",
            "https://agent.example.com/chat",
            ["accept", "accept-encoding", "connection", "content-length", "content-type", "host"],
            "application/json",
            json.dumps({"message": turn}, separators=(",", ":")).encode(),
        )
        for turn in ("First turn.", "Second turn.")
    ]
    assert result.probe_markers == []


@pytest.mark.parametrize(
    "protocol", [ProtocolType.REST, ProtocolType.OPENAI, ProtocolType.MCP, ProtocolType.A2A]
)
def test_every_protocol_handler_sends_through_the_marked_client(protocol: ProtocolType) -> None:
    on = HttpAgentAdapter(_config(protocol, "both"))
    on._client = on._build_client()
    handler: Any = on._create_handler(protocol)
    assert handler._client is on._client
    assert on._client.event_hooks["request"]

    off = HttpAgentAdapter(_config(protocol, None))
    assert off._build_client().event_hooks["request"] == []


def test_probe_markers_load_from_target_yaml(tmp_path: Path) -> None:
    path = tmp_path / "target.yaml"
    path.write_text("url: https://agent.example.com\nprotocol: rest\nprobe_markers: both\n")
    assert load_target_config(path).probe_markers == "both"

    path.write_text("url: https://agent.example.com\nprotocol: rest\n")
    assert load_target_config(path).probe_markers is None

    with pytest.raises(ValidationError):
        TargetConfig(url="https://agent.example.com", probe_markers="loud")  # type: ignore[arg-type]


def test_marker_header_is_ascii_and_off_outside_an_attack() -> None:
    assert mark_probe("both") == {}  # no attack scope: discovery, utility tasks
    with probe_scope("campaign_1", "vecteur_é") as markers:
        assert mark_probe(None) == {}
        headers = mark_probe("both")
    assert headers["X-Ziran-Probe"] == "campaign_1/vecteur_%C3%A9/1"
    assert headers["X-Ziran-Probe"].isascii()
    assert TRACEPARENT.match(headers["traceparent"])
    assert [m.probe_id for m in markers] == ["campaign_1/vecteur_é/1"]


async def test_markers_survive_a_result_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    _, [result] = await _scan(monkeypatch, _config(ProtocolType.REST, "both"), [_vector()])
    loaded = AttackResult.model_validate_json(result.model_dump_json())
    assert loaded.probe_markers == result.probe_markers
    assert (
        AttackResult.model_validate(
            {k: v for k, v in result.model_dump().items() if k != "probe_markers"}
        ).probe_markers
        == []
    )

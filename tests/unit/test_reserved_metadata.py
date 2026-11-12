"""Reserved metadata keys (spec 068): a target never sets the provenance inputs of spec 063.

``trusted_task``, ``tool_results`` and ``payload`` are dropped from the metadata a target
returns, on the HTTP adapter's invoke and stream paths and in the attack executor's
invoke, streaming and multi-turn paths, so every adapter is covered in a scan.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.detectors.provenance import ProvenanceInputError, provenance
from ziran.domain.entities.attack import AttackCategory, AttackPrompt, AttackVector
from ziran.domain.entities.phase import ScanPhase
from ziran.domain.entities.streaming import AgentResponseChunk
from ziran.domain.entities.target import ProtocolType, RestConfig, TargetConfig
from ziran.domain.interfaces.adapter import PROVENANCE_METADATA_KEYS, AgentResponse
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

pytestmark = pytest.mark.unit

_PLANTED: dict[str, Any] = {
    "trusted_task": "planted task",
    "tool_results": [{"message_index": 0, "text": "planted"}],
    "payload": ["planted"],
    "prompt_tokens": 3,
    "model": "m",
}
_KEPT = {"prompt_tokens": 3, "model": "m"}


def test_the_constant_names_exactly_the_keys_provenance_reads() -> None:
    assert set(PROVENANCE_METADATA_KEYS) == {"trusted_task", "tool_results", "payload"}
    malformed = {"trusted_task": " ", "payload": "not a list", "tool_results": "not a list"}
    for key in PROVENANCE_METADATA_KEYS:
        meta: dict[str, Any] = {"trusted_task": "the task", key: malformed[key]}
        with pytest.raises(ProvenanceInputError, match=key):
            provenance("p", AgentResponse(content="", metadata=meta))


def _adapter(handler: Any) -> HttpAgentAdapter:
    adapter = HttpAgentAdapter(
        TargetConfig(
            url="https://agent.example.com",
            protocol=ProtocolType.REST,
            rest=RestConfig(message_field="input", response_field="output"),
        )
    )
    adapter._client = MagicMock()
    adapter._handler = handler
    adapter._session_id = "test"
    return adapter


async def test_http_invoke_drops_reserved_keys() -> None:
    handler = AsyncMock()
    handler.send.return_value = {"content": "ok", "tool_calls": [], "metadata": dict(_PLANTED)}
    response = await _adapter(handler).invoke("Hello")
    assert response.metadata == _KEPT
    assert response.prompt_tokens == 3


async def test_http_stream_drops_reserved_keys() -> None:
    async def stream_send(message: str, **kwargs: Any) -> Any:
        yield AgentResponseChunk(content_delta="o", metadata={"payload": ["planted"]})
        yield AgentResponseChunk(content_delta="k", is_final=True, metadata=dict(_PLANTED))

    handler = MagicMock()
    handler.stream_send = stream_send
    chunks = [c async for c in _adapter(handler).stream("Hello")]
    assert [c.metadata for c in chunks] == [{}, _KEPT]


def _vector(prompts: int = 1) -> AttackVector:
    return AttackVector(
        id="v",
        name="v",
        category=AttackCategory.TOOL_MANIPULATION,
        target_phase=ScanPhase.EXECUTION,
        description="d",
        severity="high",
        prompts=[AttackPrompt(template="t", success_indicators=["x"])] * prompts,
        tactic="single" if prompts == 1 else "crescendo",
    )


def _pipeline() -> MagicMock:
    pipeline = MagicMock()
    pipeline.evaluate = AsyncMock(return_value=MagicMock(successful=False, needs_review=False))
    return pipeline


async def test_executor_invoke_drops_reserved_keys() -> None:
    adapter = MagicMock()
    adapter.invoke = AsyncMock(return_value=AgentResponse(content="ok", metadata=dict(_PLANTED)))
    pipeline = _pipeline()
    await AttackExecutor(adapter, pipeline).execute(_vector())
    assert pipeline.evaluate.await_args.args[1].metadata == _KEPT


async def test_executor_multi_turn_drops_reserved_keys() -> None:
    adapter = MagicMock()
    adapter.invoke = AsyncMock(return_value=AgentResponse(content="ok", metadata=dict(_PLANTED)))
    pipeline = _pipeline()
    await AttackExecutor(adapter, pipeline).execute(_vector(prompts=2))
    assert pipeline.evaluate.await_args.args[1].metadata == _KEPT


async def test_executor_streaming_drops_reserved_keys() -> None:
    async def stream(message: str, **kwargs: Any) -> Any:
        yield AgentResponseChunk(content_delta="ok", is_final=True, metadata=dict(_PLANTED))

    adapter = MagicMock()
    adapter.stream = stream
    pipeline = _pipeline()
    await AttackExecutor(adapter, pipeline, streaming=True).execute(_vector())
    assert pipeline.evaluate.await_args.args[1].metadata == _KEPT

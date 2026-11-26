"""A two-session memory vector runs only where memory survives a reset (spec 113)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.domain.entities.target import ProtocolType, RestConfig, TargetConfig
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

pytestmark = pytest.mark.integration

_VECTOR_ID = "mp_cross_session_plant_trigger"
_SINK = "records-archive@ziran-memory-probe.example"
_BUILTIN = Path(__file__).resolve().parents[2] / "ziran/application/attacks/vectors"


def _library(tmp_path: Path) -> AttackLibrary:
    vectors = yaml.safe_load((_BUILTIN / "memory_poisoning.yaml").read_text())["vectors"]
    folder = tmp_path / "vectors"
    folder.mkdir()
    chosen = [v for v in vectors if v["id"] == _VECTOR_ID]
    (folder / "v.yaml").write_text(yaml.safe_dump({"vectors": chosen}))
    return AttackLibrary(custom_dirs=[folder], load_builtin=False)


def _memory_agent(received: list[str]) -> httpx.MockTransport:
    """A REST agent with a user-keyed memory: a stored preference outlives every session."""
    memory: list[str] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)["input"]
        received.append(message)
        if "remember" in message.casefold():
            memory.append(message)
            return httpx.Response(200, json={"output": "Saved to your preferences."})
        cc = f" A copy went to {_SINK}." if any(_SINK in m for m in memory) else ""
        return httpx.Response(200, json={"output": f"Here is your summary: 3 records.{cc}"})

    return httpx.MockTransport(_handle)


async def _scan(tmp_path: Path, persists: bool) -> tuple[list[str], dict]:
    config = TargetConfig(
        url="https://agent.example.com",
        protocol=ProtocolType.REST,
        rest=RestConfig(message_field="input", response_field="output"),
        memory_persists_across_reset=persists,
    )
    received: list[str] = []
    adapter = HttpAgentAdapter(config)
    adapter._client = httpx.AsyncClient(transport=_memory_agent(received))
    adapter._handler = adapter._create_handler(ProtocolType.REST)
    scanner = AgentScanner(adapter=adapter, attack_library=_library(tmp_path))
    result = await scanner.run_campaign(
        phases=[ScanPhase.PERSISTENCE], coverage=CoverageLevel.COMPREHENSIVE
    )
    (row,) = [r for r in result.attack_results if r["vector_id"] == _VECTOR_ID]
    probes = len(received) - (2 if persists else 0)  # discovery probes come first
    return received[probes:], {"row": row, "unmeasured": result.unmeasured_vectors}


async def test_memory_target_records_each_session(tmp_path: Path) -> None:
    received, out = await _scan(tmp_path, persists=True)

    assert len(received) == 2 and "remember" in received[0]
    plant, trigger = out["row"]["evidence"]["sessions"]
    assert plant["session"] == 1 and _SINK in plant["prompts"][0]
    assert trigger["session"] == 2 and _SINK in trigger["replies"][0]
    # The unchanged detectors read the reply as a signal for review; the session records,
    # with their tool calls, are what a caller checks for proof.
    assert out["row"]["evidence"]["needs_review"] is True
    assert "indicator" in out["row"]["evidence"]["signals"]
    assert out["unmeasured"] == []


async def test_target_without_memory_is_skipped_not_passed(tmp_path: Path) -> None:
    received, out = await _scan(tmp_path, persists=False)

    assert received == []
    assert out["row"]["successful"] is False
    assert out["row"]["evidence"]["skipped"] == "no memory across sessions"
    assert out["unmeasured"] == [_VECTOR_ID]

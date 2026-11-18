"""A scan of an MCP server that takes no chat prompt reads unmeasured, never passed (spec 082)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import httpx
import pytest
from click.testing import CliRunner

from ziran.application.agent_scanner.scan_cache import CacheContext, ScanCache
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.domain.entities.target import ProtocolType, TargetConfig
from ziran.infrastructure.adapters.http_adapter import CircuitState, HttpAgentAdapter
from ziran.interfaces.cli.main import cli
from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

_VECTOR = """
  - id: no_chat_{i}
    name: No chat {i}
    category: prompt_injection
    target_phase: reconnaissance
    severity: high
    description: spec 082 vector
    owasp_mapping: [LLM01]
    prompts:
      - template: "prompt number {i}"
        success_indicators: ["unlikely-indicator-xyz"]
"""


def _no_chat_server(methods: list[str]) -> httpx.MockTransport:
    """An MCP server with one tool and no chat method."""

    def _handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        methods.append(body["method"])
        if body["method"] == "tools/list":
            tools = {"tools": [{"name": "search", "description": "Search"}]}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": tools})
        error = {"code": -32601, "message": "Method not found"}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": error})

    return httpx.MockTransport(_handle)


async def test_a_no_chat_target_is_unmeasured_uncached_and_never_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    vectors = tmp_path / "vectors"
    vectors.mkdir()
    (vectors / "v.yaml").write_text("vectors:" + "".join(_VECTOR.format(i=i) for i in range(10)))
    evaluate = AsyncMock()
    monkeypatch.setattr(DetectorPipeline, "evaluate", evaluate)

    methods: list[str] = []
    adapter = HttpAgentAdapter(TargetConfig(url="https://mcp.example.com", protocol="mcp"))
    adapter._client = httpx.AsyncClient(transport=_no_chat_server(methods))
    adapter._handler = adapter._create_handler(ProtocolType.MCP)
    cache_root = tmp_path / "scan_cache"
    ctx = CacheContext(ziran_version="0.0.0", target_sha256="0" * 64)
    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(custom_dirs=[vectors], load_builtin=False),
        config={"scan_cache": ScanCache(ctx, cache_root)},
    )

    with caplog.at_level("WARNING"):
        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE],
            coverage=CoverageLevel.COMPREHENSIVE,
            max_concurrent_attacks=1,
        )

    evaluate.assert_not_called()
    assert "sampling/createMessage" not in methods
    assert adapter._circuit_breaker.state == CircuitState.CLOSED
    assert len([r for r in caplog.records if "no chat prompt" in r.getMessage()]) == 1
    assert {r["evidence"]["prompt_errors"] for r in result.attack_results} == {1}
    assert sorted(result.unmeasured_vectors) == sorted(f"no_chat_{i}" for i in range(10))
    assert result.metadata["scan_cache"] == {"executed": 10, "cached": 0}
    assert not list(cache_root.rglob("*.json"))

    reports = ReportGenerator(output_dir=tmp_path / "reports")
    markdown = reports.save_markdown(result).read_text()
    page = reports.save_html(result).read_text()
    for text in (markdown, page):
        assert "PASSED" not in text
        assert "INCOMPLETE (10 unmeasured)" in text
    assert 'sev-ok">PASS' not in page  # no OWASP row reads PASS
    gate = CliRunner().invoke(cli, ["ci", str(reports.save_json(result))])
    assert gate.exit_code != 0
    assert "None of the 10 vector(s) was measured" in gate.output

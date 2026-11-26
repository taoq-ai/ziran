"""The A2A identity probes run in a scan of an A2A target, and only there (spec 118)."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import httpx
import pytest
import yaml
from click.testing import CliRunner

from tests.a2a_servers import A2AServer
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.domain.entities.target import (
    A2AConfig,
    AuthConfig,
    AuthType,
    ProtocolType,
    RestConfig,
    TargetConfig,
)
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter
from ziran.interfaces.cli.main import cli

if TYPE_CHECKING:
    from pathlib import Path
from typing import Any

pytestmark = pytest.mark.integration


def test_scan_of_an_unsigned_card_raises_a2a_card_unsigned(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with A2AServer() as server:
        target = tmp_path / "t.yaml"
        target.write_text(yaml.safe_dump({"url": server.url, "a2a": {"blocking": True}}))
        run = CliRunner().invoke(
            cli,
            [
                "scan",
                "--target",
                str(target),
                "--protocol",
                "a2a",
                "--phases",
                "reconnaissance",
                "--output",
                str(out),
            ],
        )
    assert run.exit_code == 0, run.output
    (report,) = out.glob("*_report.json")
    rows = {r["vector_id"]: r for r in json.loads(report.read_text())["attack_results"]}
    row = rows["a2a_card_unsigned"]
    assert row["successful"] is True
    assert row["evidence"]["card_sha256"] == hashlib.sha256(server.card_bytes).hexdigest()


_TOKENS = {"tok-a": "alice", "tok-b": "bob"}


def _config(server: A2AServer, **a2a: Any) -> TargetConfig:
    auth = AuthConfig(type=AuthType.BEARER, token="tok-a")
    return TargetConfig(url=server.url, protocol=ProtocolType.A2A, auth=auth, a2a=A2AConfig(**a2a))


async def test_scan_finds_the_cross_client_context_leak() -> None:
    peer = AuthConfig(type=AuthType.BEARER, token="tok-b")
    with A2AServer(vulnerable=True, tokens=_TOKENS) as server:
        adapter = HttpAgentAdapter(_config(server, peer_auth=peer))
        scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())
        result = await scanner.run_campaign(
            phases=[ScanPhase.VULNERABILITY_DISCOVERY], coverage=CoverageLevel.STANDARD
        )
    rows = {r["vector_id"]: r for r in result.attack_results}
    row = rows["a2a_cross_client_context"]
    assert row["successful"] is True and row["severity"] == "high"
    assert len(row["evidence"]["requests"]) == 2
    assert "a2a_cross_client_context" in result.phases_executed[0].vulnerabilities_found


@pytest.mark.parametrize("tokens", [_TOKENS, {}], ids=["bearer", "no-auth"])
async def test_a_safe_target_with_unset_probe_inputs_stays_passed(tokens: dict[str, str]) -> None:
    with A2AServer(vulnerable=False, signed=True, tokens=tokens) as server:
        config = _config(server)
        if not tokens:
            config.auth = None
        scanner = AgentScanner(adapter=HttpAgentAdapter(config), attack_library=AttackLibrary())
        result = await scanner.run_campaign(
            phases=[ScanPhase.RECONNAISSANCE, ScanPhase.VULNERABILITY_DISCOVERY],
            coverage=CoverageLevel.STANDARD,
        )
    ran = {r["vector_id"] for r in result.attack_results}
    assert {"a2a_card_unsigned", "a2a_card_signature_invalid"} <= ran
    assert not ran & {"a2a_cross_client_context", "a2a_delegated_token_replay"}
    assert result.success is False and result.unmeasured_vectors == []  # PASSED
    assert any("a2a_lookalike_card (set a2a.lookalike_cards)" in w for w in result.warnings)


async def test_probes_do_not_run_on_another_protocol() -> None:
    def _rest(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"output": "Hello."})

    config = TargetConfig(
        url="https://agent.example.com",
        protocol=ProtocolType.REST,
        rest=RestConfig(message_field="input", response_field="output"),
    )
    adapter = HttpAgentAdapter(config)
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(_rest))
    adapter._handler = adapter._create_handler(ProtocolType.REST)
    scanner = AgentScanner(adapter=adapter, attack_library=AttackLibrary())
    result = await scanner.run_campaign(
        phases=[ScanPhase.RECONNAISSANCE], coverage=CoverageLevel.COMPREHENSIVE
    )
    ran = {r["vector_id"] for r in result.attack_results}
    probes = {v.id for v in AttackLibrary().vectors if v.a2a_probe}
    assert ran and len(probes) == 6 and not ran & probes

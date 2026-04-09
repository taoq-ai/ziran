"""Unit tests for the InvariantRenderer."""

from __future__ import annotations

import pytest

from ziran.domain.entities.capability import DangerousChain
from ziran.infrastructure.policy_renderers.invariant_renderer import InvariantRenderer


def _make_chain(
    tools: list[str] | None = None,
    risk_level: str = "critical",
    vulnerability_type: str = "data_exfiltration",
) -> DangerousChain:
    return DangerousChain(
        tools=tools or ["read_file", "http_request"],
        risk_level=risk_level,
        vulnerability_type=vulnerability_type,
        exploit_description="Test chain for unit testing",
        risk_score=0.9,
    )


@pytest.fixture
def renderer() -> InvariantRenderer:
    return InvariantRenderer()


@pytest.fixture
def chain() -> DangerousChain:
    return _make_chain()


@pytest.mark.unit
class TestInvariantRenderer:
    """Tests for InvariantRenderer.render()."""

    def test_render_contains_raise(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "raise" in policy.content

    def test_render_contains_temporal_operator(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "->" in policy.content

    def test_render_contains_toolcall(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "ToolCall" in policy.content

    def test_render_contains_tool_names(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "read_file" in policy.content
        assert "http_request" in policy.content

    def test_render_contains_finding_id_header(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "# Finding: ZIR-0001" in policy.content

    def test_render_not_skipped(self, renderer: InvariantRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.skipped is False

    def test_render_sets_correct_format(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.format.value == "invariant"

    def test_render_preserves_severity(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.severity == "critical"

    def test_render_preserves_tool_chain(
        self, renderer: InvariantRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.tool_chain == ["read_file", "http_request"]

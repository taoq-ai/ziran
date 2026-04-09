"""Unit tests for the ColangRenderer."""

from __future__ import annotations

import pytest

from ziran.domain.entities.capability import DangerousChain
from ziran.infrastructure.policy_renderers.colang_renderer import ColangRenderer


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
def renderer() -> ColangRenderer:
    return ColangRenderer()


@pytest.fixture
def chain() -> DangerousChain:
    return _make_chain()


@pytest.mark.unit
class TestColangRenderer:
    """Tests for ColangRenderer.render()."""

    def test_render_contains_define_flow(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "define flow" in policy.content

    def test_render_contains_match_toolcall(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "match ToolCall" in policy.content

    def test_render_contains_abort(self, renderer: ColangRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "abort" in policy.content

    def test_render_contains_tool_names(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "read_file" in policy.content
        assert "http_request" in policy.content

    def test_render_contains_finding_id_header(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "# Finding: ZIR-0001" in policy.content

    def test_render_not_skipped(self, renderer: ColangRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.skipped is False

    def test_render_sets_correct_format(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.format.value == "colang"

    def test_render_preserves_severity(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.severity == "critical"

    def test_render_preserves_tool_chain(
        self, renderer: ColangRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.tool_chain == ["read_file", "http_request"]

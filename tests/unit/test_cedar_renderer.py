"""Unit tests for the CedarRenderer."""

from __future__ import annotations

import pytest

from ziran.domain.entities.capability import DangerousChain
from ziran.infrastructure.policy_renderers.cedar_renderer import CedarRenderer


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
def renderer() -> CedarRenderer:
    return CedarRenderer()


@pytest.fixture
def chain() -> DangerousChain:
    return _make_chain()


@pytest.mark.unit
class TestCedarRenderer:
    """Tests for CedarRenderer.render()."""

    def test_render_contains_forbid(self, renderer: CedarRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "forbid" in policy.content

    def test_render_contains_action(self, renderer: CedarRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "Action" in policy.content

    def test_render_contains_tool_names(
        self, renderer: CedarRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "read_file" in policy.content
        assert "http_request" in policy.content

    def test_render_contains_finding_id_header(
        self, renderer: CedarRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "// Finding: ZIR-0001" in policy.content

    def test_render_not_skipped_for_two_tools(
        self, renderer: CedarRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.skipped is False

    def test_render_skipped_for_three_tools(self, renderer: CedarRenderer) -> None:
        chain = _make_chain(tools=["read_file", "encode", "http_request"])
        policy = renderer.render(chain, finding_id="ZIR-0002")
        assert policy.skipped is True
        assert policy.skip_reason is not None

    def test_render_sets_correct_format(
        self, renderer: CedarRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.format.value == "cedar"

    def test_render_preserves_severity(
        self, renderer: CedarRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.severity == "critical"

    def test_render_preserves_tool_chain(
        self, renderer: CedarRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.tool_chain == ["read_file", "http_request"]

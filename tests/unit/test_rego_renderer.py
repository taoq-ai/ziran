"""Unit tests for the RegoRenderer."""

from __future__ import annotations

import pytest

from ziran.domain.entities.capability import DangerousChain
from ziran.infrastructure.policy_renderers.rego_renderer import RegoRenderer


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
def renderer() -> RegoRenderer:
    return RegoRenderer()


@pytest.fixture
def chain() -> DangerousChain:
    return _make_chain()


@pytest.mark.unit
class TestRegoRenderer:
    """Tests for RegoRenderer.render()."""

    def test_render_contains_package(self, renderer: RegoRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "package ziran.guardrails" in policy.content

    def test_render_contains_deny_rule(self, renderer: RegoRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "deny[msg]" in policy.content

    def test_render_contains_tool_names(
        self, renderer: RegoRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "read_file" in policy.content
        assert "http_request" in policy.content

    def test_render_contains_finding_id_header(
        self, renderer: RegoRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert "# Finding: ZIR-0001" in policy.content

    def test_render_not_skipped(self, renderer: RegoRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.skipped is False

    def test_render_sets_correct_format(
        self, renderer: RegoRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.format.value == "rego"

    def test_render_preserves_severity(self, renderer: RegoRenderer, chain: DangerousChain) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.severity == "critical"

    def test_render_preserves_tool_chain(
        self, renderer: RegoRenderer, chain: DangerousChain
    ) -> None:
        policy = renderer.render(chain, finding_id="ZIR-0001")
        assert policy.tool_chain == ["read_file", "http_request"]

    def test_render_three_tool_chain(self, renderer: RegoRenderer) -> None:
        chain = _make_chain(tools=["read_file", "encode", "http_request"])
        policy = renderer.render(chain, finding_id="ZIR-0002")
        assert "read_file" in policy.content
        assert "encode" in policy.content
        assert "http_request" in policy.content
        assert policy.skipped is False

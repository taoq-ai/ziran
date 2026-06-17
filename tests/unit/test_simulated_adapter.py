"""Validate SimulatedAgentAdapter against the REAL detector pipeline (spec 022, T005/T006).

The adapter is only useful if the actual `DetectorPipeline` marks its compromised
responses successful and its refusals safe — this is the riskiest mechanism, so
it is checked end-to-end against the real detectors.
"""

from __future__ import annotations

import pytest

from benchmarks.ground_truth.schema import AgentDefinition
from benchmarks.pentest_eval.simulated_adapter import SimulatedAgentAdapter
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.domain.entities.attack import AttackPrompt
from ziran.domain.entities.capability import CapabilityType

pytestmark = pytest.mark.unit


def _agent() -> AgentDefinition:
    return AgentDefinition(
        agent_id="vulnerable_x",
        name="X",
        description="d",
        framework="langchain",
        tools=[
            {
                "id": "shell",
                "name": "Shell",
                "description": "runs commands",
                "risk_level": "critical",
            }
        ],
        known_vulnerabilities=[
            {"type": "excessive_agency", "severity": "critical", "reference": "OWASP-LLM08"}
        ],
    )


def _adapter() -> SimulatedAgentAdapter:
    return SimulatedAgentAdapter.from_prompt_map(
        _agent(),
        vulnerable_owasp={"LLM08"},
        prompt_map={"ATTACK-LLM08": {"LLM08"}, "ATTACK-LLM01": {"LLM01"}},
    )


async def test_vulnerable_attack_is_marked_successful_by_real_pipeline() -> None:
    adapter = _adapter()
    response = await adapter.invoke("ATTACK-LLM08")
    verdict = await DetectorPipeline().evaluate(
        "ATTACK-LLM08", response, AttackPrompt(template="t")
    )
    assert verdict.successful is True  # dangerous tool call → side-effect detector fires


async def test_non_vulnerable_attack_is_refused() -> None:
    adapter = _adapter()
    response = await adapter.invoke("ATTACK-LLM01")  # agent not vulnerable to LLM01
    verdict = await DetectorPipeline().evaluate(
        "ATTACK-LLM01", response, AttackPrompt(template="t")
    )
    assert verdict.successful is False  # refusal → not successful


async def test_unresolved_prompt_refuses() -> None:
    adapter = _adapter()
    response = await adapter.invoke("totally-unknown-prompt")
    verdict = await DetectorPipeline().evaluate("x", response, AttackPrompt(template="t"))
    assert verdict.successful is False


async def test_capabilities_reflect_tools() -> None:
    caps = await _adapter().discover_capabilities()
    assert len(caps) == 1
    assert caps[0].type == CapabilityType.TOOL
    assert caps[0].dangerous is True

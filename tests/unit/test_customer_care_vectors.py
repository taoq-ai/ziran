"""Customer-care abuse vectors (spec 114): refund, discount, identity and other-customer reads.

A scripted support agent with refund and order tools runs each vector through the real
executor and detector pipeline. A finding needs a tool call that carries the vector's own
values (a refund amount, a discount, another customer's id); a refusal that quotes them, or a
call about the signed-in customer, is no finding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.detectors.pipeline import DetectorPipeline
from ziran.domain.interfaces.adapter import AgentResponse

if TYPE_CHECKING:
    from ziran.application.attacks.library import AttackLibrary
    from ziran.domain.entities.attack import AttackVector

pytestmark = pytest.mark.unit

FAMILIES = {"refund_abuse", "discount_override", "identity_bypass", "other_customer_read"}
# The signed-in customer: values the agent may take from its session, never from the prompt.
OWN = {"customer_id": "CUST-10000001", "order_id": "ORD-10000001"}
REFUSAL = "I'm sorry, but I can't do that."


def _vectors(lib: AttackLibrary) -> list[AttackVector]:
    return [v for v in lib.vectors if "spec-114" in v.tags]


def _agent(content: str, calls: list[dict[str, Any]]) -> MagicMock:
    adapter = MagicMock()
    adapter.invoke = AsyncMock(
        side_effect=lambda *_a, **_k: AgentResponse(content=content, tool_calls=calls)
    )
    return adapter


async def _run(vector: AttackVector, content: str, calls: list[dict[str, Any]]) -> bool:
    result = await AttackExecutor(_agent(content, calls), DetectorPipeline()).execute(vector)
    return result.successful


def test_two_vectors_per_family_with_sources_and_mappings(
    shared_attack_library: AttackLibrary,
) -> None:
    vectors = _vectors(shared_attack_library)
    assert len(vectors) == 8
    families = [t for v in vectors for t in v.tags if t in FAMILIES]
    assert sorted(set(families)) == sorted(FAMILIES)
    assert all(families.count(f) >= 2 for f in FAMILIES)
    for v in vectors:
        assert v.references and all(r.startswith("https://") for r in v.references), v.id
        assert v.owasp_mapping and v.owasp_agentic_mapping and v.atlas_mapping, v.id


def test_every_prompt_names_its_evidence_values(shared_attack_library: AttackLibrary) -> None:
    """Each variable is a value the abusive call carries; it must reach the rendered prompt."""
    for v in _vectors(shared_attack_library):
        for p in v.prompts:
            assert p.variables, v.id
            rendered = AttackExecutor._render_prompt(p)
            for value in p.variables.values():
                assert len(value) >= 3 and value in rendered, (v.id, value)


async def test_a_call_with_the_vector_values_is_a_finding(
    shared_attack_library: AttackLibrary,
) -> None:
    for v in _vectors(shared_attack_library):
        args = dict(v.prompts[0].variables)
        calls = [{"tool": "issue_refund", "input": args}]
        assert await _run(v, "Done, that is processed.", calls), v.id


async def test_a_refusal_that_quotes_the_values_is_no_finding(
    shared_attack_library: AttackLibrary,
) -> None:
    for v in _vectors(shared_attack_library):
        quoted = " ".join(v.prompts[0].variables.values())
        assert not await _run(v, f"{REFUSAL} You asked about {quoted}.", []), v.id


async def test_a_call_about_the_signed_in_customer_is_no_finding(
    shared_attack_library: AttackLibrary,
) -> None:
    calls = [
        {"tool": "get_order", "input": OWN},
        {"tool": "get_customer", "input": {"customer_id": OWN["customer_id"]}},
    ]
    for v in _vectors(shared_attack_library):
        assert not await _run(v, "Sure, here is your latest order and account.", calls), v.id

"""Linear-time provenance patterns (spec 068): equal to the frozen ones, and fast on 1 MB.

The ``_OLD`` patterns are the ones of spec 063, as ``study/scripts/g10_dev_probe.py`` in
taoq-ai/ziran-paper wrote them (the parity test keeps a copy of the whole probe). The
mail and domain patterns backtrack over every start in a long run, so a 64k-character
argument took 41 s; the CamelCase split did the same on a run of capitals.
"""

from __future__ import annotations

import random
import re
import time
from typing import TYPE_CHECKING

import pytest

from ziran.application.detectors import provenance as module
from ziran.application.detectors.provenance import atoms, provenance, tokens
from ziran.application.knowledge_graph.role_typing import tool_roles
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name
from ziran.domain.interfaces.adapter import AgentResponse

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.unit

_OLD_PARTS = (
    re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    re.compile(r"https?://[^\s<>\"']+"),
    re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"),
    re.compile(r"\b(?=[a-z]*\d)[a-z0-9]{8,}\b"),
    re.compile(r"(?<!\w)\d{3,}(?:[.,]\d+)?(?!\w)"),
)
_OLD_CAMEL = (re.compile(r"([a-z0-9])([A-Z])"), re.compile(r"([A-Z]+)([A-Z][a-z])"))

# every class boundary the patterns test, and the shapes that made them quadratic
_ALPHABET = [
    *"abzAZ019.@+-_ é:/<'\n",
    *("a.", "aa", "AB", "ABc", "com", "http://", "x1y2", "a@b.c", "@d.e", ".co", "-x."),
]
_INPUTS = 300_000


def _old_findall(text: str) -> list[str]:
    return [m for p in _OLD_PARTS for m in p.findall(text)]


def _old_tokens(name: str) -> list[str]:
    for pattern in _OLD_CAMEL:
        name = pattern.sub(r"\1 \2", name)
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", name) if t]


def _random(rng: random.Random) -> str:
    text = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 30)))
    if rng.random() < 0.05:  # a long adversarial run inside the noise
        text += rng.choice(["a", "a.", "A", "a-", "1.", "a@"]) * rng.randint(50, 200)
    return text


def test_patterns_equal_the_frozen_ones_on_random_inputs() -> None:
    rng = random.Random(68)
    differences = {"parts": 0, "tokens": 0}
    for _ in range(_INPUTS):
        text = _random(rng)
        new = [m for p in module._PARTS for m in p.findall(text) if m]
        differences["parts"] += new != _old_findall(text)
        differences["tokens"] += tokens(text) != _old_tokens(text)
    assert differences == {"parts": 0, "tokens": 0}


def test_atoms_of_a_long_value_equal_the_frozen_findall() -> None:
    value = "Mail dana.lee@example.com, see https://x.example.org/a?b=1 or acme.io; ref ab12cd34ef 1250.50"
    text = module.norm(value)
    assert [a for _, a in atoms({"body": value})] == _old_findall(text)


def _assert_linear(run: Callable[[int], object]) -> None:
    """Quadrupling the input stays under 8 times the time (a quadratic pattern takes about 16)."""

    def best(size: int) -> float:
        times = []
        for _ in range(3):
            start = time.perf_counter()
            run(size)
            times.append(time.perf_counter() - start)
        return min(times)

    small, large = best(256_000), best(1_000_000)
    assert large < 10.0  # backstop; the runner's speed sets the rest
    assert large / small < 8, (small, large)


@pytest.mark.parametrize("unit", ["a", "a.", "A", "a-", "1.", "a@", "aA", "x1"])
def test_a_1mb_argument_scales_linearly(unit: str) -> None:
    def run(size: int) -> object:
        call = {"tool": "send_email", "arguments": {"body": unit * (size // len(unit))}}
        response = AgentResponse(
            content="", tool_calls=[{**call, "message_index": 1}], metadata={"payload": ["x"]}
        )
        return provenance("p", response)

    _assert_linear(run)


@pytest.mark.parametrize("unit", ["A", "Ab", "a", "aB", "A_", "1A"])
def test_a_1mb_tool_name_scales_linearly(unit: str) -> None:
    _assert_linear(lambda size: tokens(canonical_tool_name(unit * (size // len(unit)))))


def test_tool_roles_of_a_1mb_name_scales_linearly() -> None:
    _assert_linear(lambda size: tool_roles("A" * size))

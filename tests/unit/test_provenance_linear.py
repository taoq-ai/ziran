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

import pytest

from ziran.application.detectors import provenance as module
from ziran.application.detectors.provenance import atoms, provenance, tokens
from ziran.application.knowledge_graph.tool_aliases import canonical_tool_name
from ziran.domain.interfaces.adapter import AgentResponse

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


@pytest.mark.parametrize("unit", ["a", "a.", "A", "a-", "1.", "a@", "aA", "x1"])
def test_a_1mb_argument_runs_in_under_a_second(unit: str) -> None:
    arg = unit * (1_000_000 // len(unit))
    response = AgentResponse(
        content="",
        tool_calls=[{"tool": "send_email", "arguments": {"body": arg}, "message_index": 1}],
        metadata={"payload": ["injected"]},
    )
    start = time.perf_counter()
    provenance("p", response)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("unit", ["A", "Ab", "a", "aB", "A_", "1A"])
def test_a_1mb_tool_name_runs_in_under_a_second(unit: str) -> None:
    name = unit * (1_000_000 // len(unit))
    start = time.perf_counter()
    tokens(canonical_tool_name(name))  # the work of tool_roles (spec 066)
    assert time.perf_counter() - start < 1.0


def test_tool_roles_of_a_1mb_name_runs_in_under_a_second() -> None:
    # role_typing lands with spec 066 (ziran#492); until then this test skips
    role_typing = pytest.importorskip("ziran.application.knowledge_graph.role_typing")
    start = time.perf_counter()
    role_typing.tool_roles("A" * 1_000_000)
    assert time.perf_counter() - start < 1.0

"""hybrid_route_share and the pending rule (spec 064)."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from ziran.application.hybrid import decide, routed
from ziran.application.hybrid.prompts import load
from ziran.infrastructure.llm.base import LLMResponse
from ziran.infrastructure.llm.replay_client import RecordReplayClient, request_key

FIXTURES = Path(__file__).parents[1] / "fixtures" / "hybrid_prompts"
PACKAGE = Path(__file__).parents[2] / "ziran"
MODEL, VERSION = "gpt-5.6-luna", "codex-cli 0.163.0"


def _render(unit: str) -> str:
    return f"trace of {unit}"


def _parse(content: str) -> str | None:
    reply = json.loads(content)
    verdict = reply.get("verdict")
    return verdict if verdict in ("completed", "attempted", "none") else None


def _sha(unit: str) -> str:
    return hashlib.sha256(unit.encode()).hexdigest()


# ── Routing order ────────────────────────────────────────────────────


@pytest.mark.unit
def test_band_units_are_taken_in_sha256_order() -> None:
    units = [f"u-{i}" for i in range(20)]
    assert routed(units, 1.0) == sorted(units, key=_sha)
    assert routed(list(reversed(units)), 1.0) == sorted(units, key=_sha)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("share", "n", "sent"),
    [(0.0, 10, 0), (0.25, 10, 2), (0.5, 10, 5), (0.75, 4, 3), (1.0, 7, 7), (0.29, 100, 29)],
)
def test_the_share_rounds_down_to_whole_units(share: float, n: int, sent: int) -> None:
    units = [f"u-{i}" for i in range(n)]
    got = routed(units, share)
    assert got == sorted(units, key=_sha)[:sent]


@pytest.mark.unit
@pytest.mark.parametrize("share", [-0.01, 1.01, float("nan"), float("inf")])
def test_a_share_outside_zero_to_one_is_refused(share: float) -> None:
    with pytest.raises(ValueError, match="hybrid_route_share"):
        routed(["u-1"], share)


@pytest.mark.unit
def test_duplicate_unit_ids_are_refused() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        routed(["u-1", "u-1"], 1.0)


# ── decide ───────────────────────────────────────────────────────────


@pytest.mark.unit
async def test_default_share_makes_no_call_and_keeps_every_verdict() -> None:
    first_pass = {"u-1": "attempted", "u-2": "none"}
    prompt = load("trace_judge", 0, root=FIXTURES)
    result = await decide(first_pass, None, prompt, _render, _parse)
    assert result.verdicts == first_pass
    assert result.sent == [] and result.llm_pending == []


@pytest.mark.unit
async def test_a_share_above_zero_needs_a_client() -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    with pytest.raises(ValueError, match="client"):
        await decide({"u-1": "none"}, None, prompt, _render, _parse, share=0.5)


@pytest.mark.unit
async def test_replay_uses_a_stored_reply_and_counts_a_missing_key_as_pending(
    tmp_path: Path,
) -> None:
    """Acceptance 3."""
    prompt = load("trace_judge", 0, root=FIXTURES)
    key = request_key(prompt.text, MODEL, VERSION, _render("u-1"))
    row = {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": "reply"}
    replies = tmp_path / "outcomes.jsonl"
    replies.write_text(json.dumps({**row, "fields": {"verdict": "completed", "call": 0}}) + "\n")
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    first_pass = {"u-1": "attempted", "u-2": "attempted"}
    result = await decide(first_pass, client, prompt, _render, _parse, share=1.0)
    assert result.verdicts == {"u-1": "completed", "u-2": "attempted"}
    assert result.llm_pending == ["u-2"]
    assert sorted(result.sent) == ["u-1", "u-2"]


@pytest.mark.unit
async def test_record_mode_keeps_every_verdict_and_counts_every_sent_unit(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    out = tmp_path / "judge.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    first_pass = {f"u-{i}": "attempted" for i in range(4)}
    result = await decide(first_pass, client, prompt, _render, _parse, share=0.5)
    assert result.verdicts == first_pass
    assert result.llm_pending == result.sent == routed(list(first_pass), 0.5)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["unit"] for r in rows] == result.sent
    assert {r["job"] for r in rows} == {"trace_judge"}


@pytest.mark.unit
async def test_an_unparsable_reply_keeps_the_verdict_and_counts_as_pending(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    key = request_key(prompt.text, MODEL, VERSION, _render("u-1"))
    row = {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": "reply"}
    replies = tmp_path / "outcomes.jsonl"
    replies.write_text(json.dumps({**row, "fields": {"verdict": "maybe"}}) + "\n")
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    result = await decide({"u-1": "none"}, client, prompt, _render, _parse, share=1.0)
    assert result.verdicts == {"u-1": "none"} and result.llm_pending == ["u-1"]


class _FreeText(RecordReplayClient):
    """A live client's free-text reply, as a LiteLLM client would give."""

    async def complete(self, messages: list[dict[str, str]], **kwargs: object) -> LLMResponse:
        return LLMResponse(content="I think it completed.")


@pytest.mark.unit
async def test_a_reply_that_is_not_json_keeps_the_verdict(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    client = _FreeText(MODEL, VERSION, record_to=tmp_path / "x.requests.jsonl")
    result = await decide({"u-1": "none"}, client, prompt, _render, _parse, share=1.0)
    assert result.verdicts == {"u-1": "none"} and result.llm_pending == ["u-1"]


# ── Deterministic mode is untouched (acceptance 4) ───────────────────


@pytest.mark.unit
def test_no_existing_module_imports_the_seam() -> None:
    """With nothing importing them, no shipped path (detectors, benchmarks) can change."""
    seam = ("ziran.application.hybrid", "ziran.infrastructure.llm.replay_client")
    hybrid = PACKAGE / "application" / "hybrid"
    importers = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if hybrid in path.parents or path.name == "replay_client.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            if any(n.startswith(seam) for n in names):
                importers.append(str(path.relative_to(PACKAGE)))
    assert importers == []

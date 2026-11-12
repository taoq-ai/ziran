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


def _parse(unit: str, content: str) -> str | None:
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
    [
        (0.0, 10, 0),
        (0.25, 10, 2),
        (0.5, 10, 5),
        (0.75, 4, 3),
        (0.75, 10, 7),
        (0.5, 7, 3),
        (1.0, 7, 7),
        (0.29, 100, 29),
    ],
)
def test_the_share_rounds_down_to_whole_units(share: float, n: int, sent: int) -> None:
    units = [f"u-{i}" for i in range(n)]
    got = routed(units, share)
    assert got == sorted(units, key=_sha)[:sent]


@pytest.mark.unit
@pytest.mark.parametrize("share", [-0.01, 1.01, float("nan"), float("inf"), True, "0.5"])
def test_a_share_outside_zero_to_one_is_refused(share: float) -> None:
    with pytest.raises(ValueError, match="hybrid_route_share"):
        routed(["u-1"], share)


@pytest.mark.unit
def test_duplicate_unit_ids_are_refused() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        routed(["u-1", "u-1"], 1.0)


# ── decide ───────────────────────────────────────────────────────────


def _reply_wins(first: str, reply: str) -> str:
    return reply


def _hit_stays(first: str, reply: str) -> str:
    """A job's merge rule: a provenance hit stays an attempt whatever the judge says."""
    return first if first == "hit" else reply


def _replies(tmp_path: Path, prompt_text: str, fields: dict[str, dict[str, object]]) -> Path:
    path = tmp_path / "outcomes.jsonl"
    rows = [
        {
            "key": request_key(prompt_text, MODEL, VERSION, _render(unit)),
            "unit": unit,
            "job": "trace_judge",
            "outcome": "reply",
            "fields": f,
        }
        for unit, f in fields.items()
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


@pytest.mark.unit
async def test_default_share_makes_no_call_and_keeps_every_verdict() -> None:
    first_pass = {"u-1": "attempted", "u-2": "none"}
    prompt = load("trace_judge", 0, root=FIXTURES)
    result = await decide(first_pass, ["u-1"], None, prompt, _render, _parse, merge=_reply_wins)
    assert result.verdicts == first_pass
    assert result.sent == [] and result.llm_pending == {}


@pytest.mark.unit
async def test_a_share_above_zero_needs_a_client() -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    with pytest.raises(ValueError, match="client"):
        await decide(
            {"u-1": "none"}, ["u-1"], None, prompt, _render, _parse, merge=_reply_wins, share=0.5
        )


@pytest.mark.unit
async def test_a_band_unit_with_no_first_pass_verdict_is_refused() -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    with pytest.raises(ValueError, match="first-pass"):
        await decide({"u-1": "none"}, ["u-2"], None, prompt, _render, _parse, merge=_reply_wins)


@pytest.mark.unit
async def test_replay_uses_a_stored_reply_and_counts_a_missing_key_as_pending(
    tmp_path: Path,
) -> None:
    """Acceptance 3."""
    prompt = load("trace_judge", 0, root=FIXTURES)
    replies = _replies(tmp_path, prompt.text, {"u-1": {"verdict": "completed", "call": 0}})
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    first_pass = {"u-1": "attempted", "u-2": "attempted"}
    result = await decide(
        first_pass, list(first_pass), client, prompt, _render, _parse, merge=_reply_wins, share=1.0
    )
    assert result.verdicts == {"u-1": "completed", "u-2": "attempted"}
    assert result.llm_pending == {"u-2": "missing"}
    assert sorted(result.sent) == ["u-1", "u-2"]


@pytest.mark.unit
async def test_a_provenance_hit_stays_an_attempt_when_the_judge_says_none(tmp_path: Path) -> None:
    """Goal probe A: the job's merge rule keeps a first-pass decision the protocol keeps."""
    prompt = load("trace_judge", 0, root=FIXTURES)
    replies = _replies(
        tmp_path, prompt.text, {"u-1": {"verdict": "none"}, "u-2": {"verdict": "none"}}
    )
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    first_pass = {"u-1": "hit", "u-2": "attempted"}
    result = await decide(
        first_pass, list(first_pass), client, prompt, _render, _parse, merge=_hit_stays, share=1.0
    )
    assert result.verdicts == {"u-1": "hit", "u-2": "none"}


@pytest.mark.unit
async def test_a_unit_outside_the_band_is_never_sent_or_changed(tmp_path: Path) -> None:
    """Goal probe B: a stored reply for a non-band negative is never read."""
    prompt = load("trace_judge", 0, root=FIXTURES)
    replies = _replies(
        tmp_path, prompt.text, {"neg": {"verdict": "completed"}, "u-1": {"verdict": "completed"}}
    )
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    first_pass = {"neg": "none", "u-1": "attempted"}
    result = await decide(
        first_pass, ["u-1"], client, prompt, _render, _parse, merge=_reply_wins, share=1.0
    )
    assert result.verdicts == {"neg": "none", "u-1": "completed"}
    assert result.sent == ["u-1"]


@pytest.mark.unit
async def test_record_mode_keeps_every_verdict_and_counts_every_sent_unit(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    out = tmp_path / "judge.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    first_pass = {f"u-{i}": "attempted" for i in range(4)}
    result = await decide(
        first_pass, list(first_pass), client, prompt, _render, _parse, merge=_reply_wins, share=0.5
    )
    assert result.verdicts == first_pass
    assert result.sent == routed(list(first_pass), 0.5)
    assert result.llm_pending == dict.fromkeys(result.sent, "recorded")
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["unit"] for r in rows] == result.sent
    assert {r["job"] for r in rows} == {"trace_judge"}


def _anything(unit: str, content: str) -> str:
    """A job parse that turns any content, the empty string included, into a verdict."""
    return "completed"


@pytest.mark.unit
async def test_a_pending_reply_is_never_parsed_even_by_a_parse_that_accepts_anything(
    tmp_path: Path,
) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    recorder = RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "j.requests.jsonl")
    replayer = RecordReplayClient(MODEL, VERSION, replies=_replies(tmp_path, prompt.text, {}))
    for client, cause in ((recorder, "recorded"), (replayer, "missing")):
        result = await decide(
            {"u-1": "none"},
            ["u-1"],
            client,
            prompt,
            _render,
            _anything,
            merge=_reply_wins,
            share=1.0,
        )
        assert result.verdicts == {"u-1": "none"}
        assert result.llm_pending == {"u-1": cause}


@pytest.mark.unit
async def test_a_stored_non_reply_outcome_is_the_pending_cause(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    key = request_key(prompt.text, MODEL, VERSION, _render("u-1"))
    replies = tmp_path / "outcomes.jsonl"
    row = {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": "no_text", "fields": None}
    replies.write_text(json.dumps(row) + "\n")
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    result = await decide(
        {"u-1": "none"}, ["u-1"], client, prompt, _render, _anything, merge=_reply_wins, share=1.0
    )
    assert result.verdicts == {"u-1": "none"} and result.llm_pending == {"u-1": "no_text"}


@pytest.mark.unit
async def test_an_unparsable_reply_keeps_the_verdict_and_counts_as_pending(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    client = RecordReplayClient(
        MODEL, VERSION, replies=_replies(tmp_path, prompt.text, {"u-1": {"verdict": "maybe"}})
    )
    result = await decide(
        {"u-1": "none"}, ["u-1"], client, prompt, _render, _parse, merge=_reply_wins, share=1.0
    )
    assert result.verdicts == {"u-1": "none"}
    assert result.llm_pending == {"u-1": "unusable_reply"}


class _FreeText(RecordReplayClient):
    """A live client's free-text reply, as a LiteLLM client would give."""

    async def complete(self, messages: list[dict[str, str]], **kwargs: object) -> LLMResponse:
        return LLMResponse(content="I think it completed.")


@pytest.mark.unit
async def test_a_reply_that_is_not_json_keeps_the_verdict(tmp_path: Path) -> None:
    prompt = load("trace_judge", 0, root=FIXTURES)
    client = _FreeText(MODEL, VERSION, record_to=tmp_path / "x.requests.jsonl")
    result = await decide(
        {"u-1": "none"}, ["u-1"], client, prompt, _render, _parse, merge=_reply_wins, share=1.0
    )
    assert result.verdicts == {"u-1": "none"}
    assert result.llm_pending == {"u-1": "unusable_reply"}


# ── Deterministic mode is untouched (acceptance 4) ───────────────────

SEAM = ("ziran.application.hybrid", "ziran.infrastructure.llm.replay_client")


def _imported(path: Path, package: str) -> list[str]:
    """Every module an import in ``path`` can bind, relative imports resolved against
    ``package`` and ``from a import b`` read as both ``a`` and ``a.b``."""
    names = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                base = f"{parent}.{base}" if base else parent
            names += [base, *(f"{base}.{a.name}" for a in node.names)]
    return names


def _is_seam(name: str) -> bool:
    return any(name == s or name.startswith(s + ".") for s in SEAM)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "package"),
    [
        ("import ziran.application.hybrid", "ziran.cli"),
        ("from ziran.application import hybrid", "ziran.cli"),
        ("from ziran.application.hybrid.prompts import load", "ziran.cli"),
        ("from ziran.infrastructure.llm import replay_client", "ziran.cli"),
        ("from ..infrastructure.llm import replay_client", "ziran.application"),
        ("from . import hybrid", "ziran.application"),
        ("from .hybrid import decide", "ziran.application"),
    ],
)
def test_the_import_guard_catches_every_form(tmp_path: Path, source: str, package: str) -> None:
    path = tmp_path / "m.py"
    path.write_text(source + "\n")
    assert any(_is_seam(n) for n in _imported(path, package))


@pytest.mark.unit
def test_the_import_guard_passes_lookalikes(tmp_path: Path) -> None:
    path = tmp_path / "m.py"
    path.write_text(
        "from ziran.application import hybridish\nimport ziran.infrastructure.llm.base\n"
    )
    assert not any(_is_seam(n) for n in _imported(path, "ziran.application"))


@pytest.mark.unit
def test_no_existing_module_imports_the_seam() -> None:
    """With nothing importing them, no shipped path (detectors, benchmarks) can change."""
    hybrid = PACKAGE / "application" / "hybrid"
    importers = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if hybrid in path.parents or path.name == "replay_client.py":
            continue
        rel = path.relative_to(PACKAGE.parent).with_suffix("")
        if any(_is_seam(n) for n in _imported(path, ".".join(rel.parts[:-1]))):
            importers.append(str(rel))
    assert importers == []

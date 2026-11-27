"""``ziran scan --attacker-cassette`` (spec 132): record a TAP tree, repeat it with no attacker."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from tests.unit.test_campaign_executor import (
    EXAMPLES,
    LIVE,
    TAP,
    FakeAttacker,
    ShellAgent,
    example,
    run,
    tree,
)
from ziran.application.attacks.library import AttackLibrary
from ziran.infrastructure.llm.attacker_cassette import Cassette, Recorder
from ziran.infrastructure.llm.base import LLMResponse
from ziran.interfaces.cli.main import cli

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    monkeypatch.chdir(tmp_path)
    Path("agent.py").write_text("agent_executor = None\n", encoding="utf-8")
    lib = AttackLibrary(custom_dirs=[EXAMPLES], load_builtin=False)
    made: list[dict[str, Any]] = []

    def create(**kw: Any) -> FakeAttacker:
        made.append(kw)
        return FakeAttacker()

    monkeypatch.setattr("ziran.interfaces.cli.main.AttackLibrary", lambda **kw: lib)
    monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", lambda *a: ShellAgent())
    monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", create)
    return {"made": made}


def _scan(*extra: str, code: int = 0) -> tuple[Any, dict[str, dict[str, Any]]]:
    args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--output", "out"]
    result = CliRunner().invoke(cli, [*args, "--phases", "execution", *extra])
    assert result.exit_code == code, result.output
    reports = sorted(Path("out").glob("*_report.json"))
    rows = json.loads(reports[-1].read_text(encoding="utf-8"))["attack_results"] if reports else []
    return result, {r["vector_id"]: r for r in rows}


def test_acceptance_a_recorded_tree_repeats_with_no_attacker(env: dict[str, Any]) -> None:
    _, live = _scan("--attacker-model", "fake-attacker", "--attacker-cassette", "att.jsonl")
    live_row = live[TAP]
    assert live_row["evidence"]["campaign"]["stop"] == "goal_met"
    text = Path("att.jsonl").read_text(encoding="utf-8")
    nodes = sum(len(r["evidence"]["campaign"]["nodes"]) for r in live.values())
    assert text.count("\n") == nodes

    env["made"].clear()
    _, replayed = _scan("--attacker-cassette", "att.jsonl")
    assert env["made"] == []  # no client built, no key read
    for vector_id, row in live.items():
        assert replayed[vector_id]["evidence"]["campaign"] == row["evidence"]["campaign"]


def test_a_missing_reply_stops_the_vector_pending(env: dict[str, Any]) -> None:
    Path("att.jsonl").touch()
    _, rows = _scan("--attacker-cassette", "att.jsonl")
    for row in rows.values():
        assert row["evidence"]["campaign"]["stop"] == "pending"
        assert row["evidence"]["outcome"] == "unmeasured"


def test_replay_needs_an_existing_file(env: dict[str, Any]) -> None:
    result, _ = _scan("--attacker-cassette", "nope.jsonl", code=1)
    assert "no such file" in " ".join(result.output.split())


def test_a_symlinked_cassette_is_refused(env: dict[str, Any]) -> None:
    Path("real.jsonl").touch()
    Path("link.jsonl").symlink_to("real.jsonl")
    for extra in (("--attacker-model", "m"), ()):
        result, _ = _scan(*extra, "--attacker-cassette", "link.jsonl", code=1)
        assert "symlink" in " ".join(result.output.split())
    assert Path("real.jsonl").read_text(encoding="utf-8") == ""


# -- the cassette module (quality gate, round 1) ------------------------------

MSGS = [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]


async def _record(path: Path, content: str, user: str = "U") -> None:
    rec = Recorder(FakeAttacker(replies=[content]), path)
    await rec.complete([MSGS[0], {"role": "user", "content": user}])


async def test_a_planted_tmp_symlink_is_not_followed(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    victim.chmod(0o644)
    (tmp_path / "att.jsonl.tmp").symlink_to(victim)
    await _record(tmp_path / "att.jsonl", '{"a": 1}')
    assert victim.read_text(encoding="utf-8") == "keep"
    assert victim.stat().st_mode & 0o777 == 0o644
    assert not (tmp_path / "att.jsonl").is_symlink()


async def test_the_cassette_is_0600_and_leaves_no_temp(tmp_path: Path) -> None:
    await _record(tmp_path / "att.jsonl", '{"a": 1}')
    assert (tmp_path / "att.jsonl").stat().st_mode & 0o777 == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["att.jsonl"]


async def test_a_second_record_run_keeps_earlier_rows(tmp_path: Path) -> None:
    path = tmp_path / "att.jsonl"
    await _record(path, '{"a": 1}', "one")
    await _record(path, '{"a": 2}', "two")
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


async def test_a_non_object_reply_is_stored_unparsed_and_stays_readable(tmp_path: Path) -> None:
    path = tmp_path / "att.jsonl"
    await _record(path, "[1]")
    assert json.loads(path.read_text(encoding="utf-8"))["outcome"] == "unparsed"
    reply = await Cassette(path).complete(MSGS)
    assert hasattr(reply, "reason")  # pending


async def test_a_parent_symlink_is_refused(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with pytest.raises(ValueError, match="symlink"):
        Recorder(FakeAttacker(), tmp_path / "link" / "att.jsonl")
    with pytest.raises(ValueError, match="symlink"):
        Cassette(tmp_path / "link" / "att.jsonl")


async def test_replay_books_the_recorded_tokens(tmp_path: Path) -> None:
    path = tmp_path / "att.jsonl"

    class Counting(FakeAttacker):
        async def complete(self, messages: Any, **kw: Any) -> LLMResponse:
            return LLMResponse(content="{}", prompt_tokens=7)

    await Recorder(Counting(), path).complete(MSGS)
    reply = await Cassette(path).complete(MSGS)
    assert (reply.prompt_tokens, reply.completion_tokens) == (7, 0)


@pytest.mark.parametrize("vector_id", [TAP, LIVE])
async def test_a_budgeted_run_repeats_with_the_same_stop(vector_id: str, tmp_path: Path) -> None:
    path = tmp_path / "att.jsonl"
    cap = 1500
    live = await run(
        example(vector_id), attacker=Recorder(FakeAttacker(tokens=400), path), max_tokens=cap
    )
    assert tree(live)["stop"] == "budget"
    replayed = await run(example(vector_id), attacker=Cassette(path), max_tokens=cap)
    assert tree(replayed) == tree(live)


def test_a_deeply_nested_line_is_a_readable_error(env: dict[str, Any]) -> None:
    row = {"key": "0" * 64, "outcome": "reply", "fields": {}}
    Path("att.jsonl").write_text(json.dumps(row)[:-1] + "[" * 100_000 + "\n", encoding="utf-8")
    result, _ = _scan("--attacker-cassette", "att.jsonl", code=1)
    assert "--attacker-cassette" in result.output and "Traceback" not in result.output


def test_an_oversize_cassette_is_refused(env: dict[str, Any], monkeypatch: Any) -> None:
    monkeypatch.setattr("ziran.infrastructure.llm.attacker_cassette._MAX_BYTES", 10)
    Path("att.jsonl").write_text("x" * 50, encoding="utf-8")
    result, _ = _scan("--attacker-cassette", "att.jsonl", code=1)
    assert "not an attacker cassette" in " ".join(result.output.split())


@pytest.mark.parametrize(("flags", "count"), [((), "0"), (("--attacker-cassette", "a.jsonl"), "2")])
def test_dry_run_counts_attacker_vectors_with_a_cassette(
    env: dict[str, Any], flags: tuple[str, ...], count: str
) -> None:
    Path("a.jsonl").touch()
    args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--dry-run", *flags]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    assert f"Attack Vectors {count} (" in " ".join(result.output.replace("│", " ").split())

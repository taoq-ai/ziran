"""``ziran scan --attacker-cassette`` (spec 132): record a TAP tree, repeat it with no attacker."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from tests.unit.test_campaign_executor import EXAMPLES, TAP, FakeAttacker, ShellAgent
from ziran.application.attacks.library import AttackLibrary
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

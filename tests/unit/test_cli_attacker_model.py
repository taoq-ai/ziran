"""``ziran scan --attacker-model`` (spec 127): PAIR vectors from the CLI, offline.

The scan is real (scanner, phases, reports); the target is the toy guard agent and the attacker
a scripted ``BaseLLMClient`` put in place of ``create_llm_client``. No live key is read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from tests.unit.test_pair_executor import SECRET, WIN, Attacker, ScriptedJudge, ToyGuardAgent
from tests.unit.test_pair_wiring import library
from ziran.interfaces.cli.main import cli

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    monkeypatch.chdir(tmp_path)
    Path("agent.py").write_text("agent_executor = None\n", encoding="utf-8")
    vectors = tmp_path / "vectors"
    vectors.mkdir()
    lib = library(vectors)
    target = ToyGuardAgent()
    attacker = Attacker(replies=[(WIN,)])
    made: list[dict[str, Any]] = []

    def create(**kw: Any) -> Attacker | ScriptedJudge:
        if kw["model"] == "judge":  # --llm-model: the quality judge that scores each attempt
            return ScriptedJudge()
        made.append(kw)
        attacker.config.model = kw["model"]
        return attacker

    monkeypatch.setattr("ziran.interfaces.cli.main.AttackLibrary", lambda **kw: lib)
    monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", lambda *a: target)
    monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", create)
    return {"target": target, "attacker": attacker, "made": made}


def _scan(*extra: str) -> tuple[Any, dict[str, Any]]:
    args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--output", "out"]
    result = CliRunner().invoke(cli, [*args, "--phases", "exploitation_setup", *extra])
    assert result.exit_code == 0, result.output
    [report] = Path("out").glob("*_report.json")
    return result, json.loads(report.read_text(encoding="utf-8"))


def test_attacker_model_runs_the_pair_loop(env: dict[str, Any]) -> None:
    result, report = _scan("--attacker-model", "openai/gpt-4o-mini", "--llm-model", "judge")
    [row] = report["attack_results"]
    assert row["vector_id"] == "pair_wired"
    assert row["successful"]
    assert row["evidence"]["pair"]["stop"] == "success"
    assert row["evidence"]["pair"]["attacker_model"] == "openai/gpt-4o-mini"
    assert SECRET in row["agent_response"]
    assert env["target"].prompts == [WIN]
    assert env["attacker"].requests  # the scripted client, called through the seam
    [kw] = env["made"]
    assert kw["model"] == "openai/gpt-4o-mini"
    assert kw["provider"] == "litellm"
    assert "pair_wired" not in json.dumps(report["metadata"].get("warnings", []))
    assert "Attacker Model" in result.output


def test_without_attacker_model_the_vector_is_not_run(env: dict[str, Any]) -> None:
    result, report = _scan()
    assert report["attack_results"] == []
    assert env["target"].prompts == []
    assert env["made"] == []
    [warning] = report["metadata"]["warnings"]
    assert "not run" in warning
    assert "pair_wired" in warning
    assert "--attacker-model" in warning
    assert "unmeasured_vectors" not in report["metadata"]
    assert "pair_wired" in result.output


def test_attacker_tokens_count_towards_the_budget(env: dict[str, Any]) -> None:
    env["attacker"].tokens = 40
    _, report = _scan("--attacker-model", "m-att", "--max-campaign-tokens", "1000")
    usage = json.dumps(report["metadata"]["usage"])
    assert "attacker" in usage
    assert "m-att" in usage


def test_unpriced_attacker_model_warns_under_max_cost(env: dict[str, Any]) -> None:
    result, _ = _scan("--attacker-model", "m-att", "--max-cost", "1")
    out = " ".join(result.output.split())
    assert "no price for model 'm-att'" in out
    assert "--max-cost cannot trigger" not in out


def test_missing_llm_extra_is_a_clear_error(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(**kw: Any) -> Attacker:
        raise ImportError("litellm is required")

    monkeypatch.setattr("ziran.infrastructure.llm.create_llm_client", missing)
    args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--output", "out"]
    result = CliRunner().invoke(cli, [*args, "--attacker-model", "m-att"])
    assert result.exit_code == 1
    assert "--attacker-model needs the llm extra" in " ".join(result.output.split())
    assert env["target"].prompts == []

"""`ziran scan --incremental` end to end through the CLI (spec 049 US1, US5.3).

Real scanner, real built-in library; only the agent loader is patched to a
non-vulnerable ``MockAgentAdapter``. Each run writes to its own ``--output``
dir because ``campaign_id`` has one-second resolution.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from tests.conftest import MockAgentAdapter
from ziran.interfaces.cli.main import cli

pytestmark = pytest.mark.integration

_ARGS = [
    "scan",
    "--framework",
    "langchain",
    "--agent-path",
    "agent.py",
    "--phases",
    "reconnaissance",
    "--phases",
    "trust_building",
    "--phases",
    "capability_mapping",
    "--coverage",
    "standard",
    "--no-stop-on-critical",
    "--concurrency",
    "1",
]


@pytest.fixture
def adapters(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[MockAgentAdapter]:
    monkeypatch.chdir(tmp_path)
    Path("agent.py").write_text("agent_executor = None\n", encoding="utf-8")
    made: list[MockAgentAdapter] = []

    def _load(*args: Any, **kwargs: Any) -> MockAgentAdapter:
        made.append(MockAgentAdapter())
        return made[-1]

    monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", _load)
    return made


def _run(*extra: str, output: str) -> tuple[Any, dict[str, Any]]:
    result = CliRunner().invoke(cli, [*_ARGS, *extra, "--output", output])
    assert result.exit_code == 0, result.output
    [report] = Path(output).glob("campaign_*_report.json")
    data: dict[str, Any] = json.loads(report.read_text())
    return result, data


def _outcomes(report: dict[str, Any]) -> set[tuple[str, bool]]:
    return {(r["vector_id"], r["successful"]) for r in report["attack_results"]}


def test_second_run_is_at_least_90_percent_cached(adapters: list[MockAgentAdapter]) -> None:
    _, first = _run("--incremental", output="out1")
    stats1 = first["metadata"]["scan_cache"]
    assert stats1["cached"] == 0
    assert stats1["executed"] == len(first["attack_results"]) > 0
    assert list(Path(".ziran/scan_cache").rglob("*.json"))

    out2, second = _run("--incremental", output="out2")
    stats2 = second["metadata"]["scan_cache"]
    ratio = stats2["cached"] / (stats2["cached"] + stats2["executed"])
    print(f"incremental cache: run 2 {stats2} ratio={ratio:.3f}")
    assert ratio >= 0.9
    assert "Incremental Cache" in out2.output
    assert second["total_vulnerabilities"] == first["total_vulnerabilities"]
    assert _outcomes(second) == _outcomes(first)
    if stats2["executed"] == 0:
        assert adapters[-1].invocations == []


def test_no_cache_neither_reads_nor_writes(adapters: list[MockAgentAdapter]) -> None:
    _run("--incremental", output="out1")
    root = Path(".ziran/scan_cache")
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert before

    _, second = _run("--incremental", "--no-cache", output="out2")
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert "scan_cache" not in second["metadata"]
    assert adapters[-1].invocations

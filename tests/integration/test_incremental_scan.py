"""Incremental scanning end to end through AgentScanner (spec 049)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.scan_cache import CacheContext, ScanCache
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.phase import CampaignResult, CoverageLevel, ScanPhase

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

_VECTOR_YAML = """
vectors:
  - id: {id}
    name: Vector {id}
    category: prompt_injection
    target_phase: {phase}
    severity: {severity}
    description: incremental scan test vector
    prompts:
      - template: "{template}"
        success_indicators: ["unlikely-indicator-xyz"]
"""


def _ctx() -> CacheContext:
    return CacheContext(ziran_version="0.0.0", target_sha256="0" * 64)


def _write_vector(path: Path, name: str, id: str, template: str, **kw: str) -> None:
    path.joinpath(name).write_text(
        _VECTOR_YAML.format(
            id=id,
            template=template,
            phase=kw.get("phase", "reconnaissance"),
            severity=kw.get("severity", "medium"),
        )
    )


def _write_vector_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for i in range(1, 6):
        sev = "critical" if i == 1 else "medium"
        _write_vector(path, f"v{i}.yaml", f"inc_v{i}", f"prompt number {i}", severity=sev)
    _write_vector(path, "t1.yaml", "inc_t1", "trust prompt", phase="trust_building")
    return path


async def _scan(
    vectors: Path,
    cache_root: Path,
    adapter: MockAgentAdapter,
    *,
    phases: list[ScanPhase] | None = None,
    stop_on_critical: bool = False,
    config: dict[str, Any] | None = None,
) -> CampaignResult:
    scanner = AgentScanner(
        adapter=adapter,
        attack_library=AttackLibrary(custom_dirs=[vectors], load_builtin=False),
        config=config if config is not None else {"scan_cache": ScanCache(_ctx(), cache_root)},
    )
    return await scanner.run_campaign(
        phases=phases or [ScanPhase.RECONNAISSANCE],
        stop_on_critical=stop_on_critical,
        coverage=CoverageLevel.COMPREHENSIVE,
        max_concurrent_attacks=1,
    )


async def test_editing_one_vector_reexecutes_only_that_vector(tmp_path: Path) -> None:
    vectors = _write_vector_dir(tmp_path / "vectors")
    root = tmp_path / "scan_cache"
    first = await _scan(vectors, root, MockAgentAdapter())
    assert first.metadata["scan_cache"] == {"executed": 5, "cached": 0}

    _write_vector(vectors, "v3.yaml", "inc_v3", "edited prompt three")
    adapter = MockAgentAdapter()
    second = await _scan(vectors, root, adapter)
    assert second.metadata["scan_cache"] == {"executed": 1, "cached": 4}
    assert adapter.invocations == ["edited prompt three"]


async def test_capability_change_invalidates_all(tmp_path: Path) -> None:
    vectors = _write_vector_dir(tmp_path / "vectors")
    root = tmp_path / "scan_cache"
    await _scan(vectors, root, MockAgentAdapter())
    extra = [AgentCapability(id="shell", name="Shell", type=CapabilityType.TOOL)]
    second = await _scan(vectors, root, MockAgentAdapter(capabilities=extra))
    assert second.metadata["scan_cache"] == {"executed": 5, "cached": 0}


async def test_cached_success_counts_in_total_vulnerabilities(tmp_path: Path) -> None:
    vectors = _write_vector_dir(tmp_path / "vectors")
    root = tmp_path / "scan_cache"
    first = await _scan(vectors, root, MockAgentAdapter(vulnerable=True))
    assert first.total_vulnerabilities > 0

    adapter = MockAgentAdapter(vulnerable=True)
    second = await _scan(vectors, root, adapter)
    assert adapter.invocations == []
    assert second.metadata["scan_cache"] == {"executed": 0, "cached": 5}
    assert second.total_vulnerabilities == first.total_vulnerabilities
    assert {(r["vector_id"], r["successful"]) for r in second.attack_results} == {
        (r["vector_id"], r["successful"]) for r in first.attack_results
    }


async def test_stop_on_critical_honoured_on_cached_run(tmp_path: Path) -> None:
    vectors = _write_vector_dir(tmp_path / "vectors")
    root = tmp_path / "scan_cache"
    phases = [ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING]
    first = await _scan(
        vectors, root, MockAgentAdapter(vulnerable=True), phases=phases, stop_on_critical=True
    )
    assert [p.phase for p in first.phases_executed] == [ScanPhase.RECONNAISSANCE]

    adapter = MockAgentAdapter(vulnerable=True)
    second = await _scan(vectors, root, adapter, phases=phases, stop_on_critical=True)
    assert adapter.invocations == []
    assert [p.phase for p in second.phases_executed] == [ScanPhase.RECONNAISSANCE]


async def test_cached_results_zero_tokens(tmp_path: Path) -> None:
    vectors = _write_vector_dir(tmp_path / "vectors")
    root = tmp_path / "scan_cache"
    await _scan(vectors, root, MockAgentAdapter())
    second = await _scan(vectors, root, MockAgentAdapter())
    assert second.token_usage["total_tokens"] == 0
    assert second.attack_results
    assert all(r["evidence"]["cached"] is True for r in second.attack_results)


async def test_no_cache_key_is_unchanged_behaviour(tmp_path: Path) -> None:
    vectors = _write_vector_dir(tmp_path / "vectors")
    root = tmp_path / "scan_cache"
    await _scan(vectors, root, MockAgentAdapter())
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}

    adapter = MockAgentAdapter()
    result = await _scan(vectors, root, adapter, config={})
    assert "scan_cache" not in result.metadata
    assert len(adapter.invocations) == 5
    assert all("cached" not in r["evidence"] for r in result.attack_results)
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before

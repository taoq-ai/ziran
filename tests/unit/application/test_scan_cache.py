"""Unit tests for the incremental scan cache (spec 049)."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest

import ziran
from ziran.application.agent_scanner.scan_cache import (
    CacheContext,
    ScanCache,
    ScanCacheStats,
    build_cache_context,
    cache_disabled_reason,
    campaign_key,
    clear_cache,
    is_cacheable,
    vector_key,
)
from ziran.application.detectors.pipeline import DetectorConfig
from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.domain.entities.attack import (
    AttackPrompt,
    AttackResult,
    AttackVector,
    TokenUsage,
)
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.phase import ScanPhase
from ziran.infrastructure.llm.base import LLMConfig

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


def _ctx(**overrides: Any) -> CacheContext:
    return CacheContext(**{"ziran_version": "0.0.0", "target_sha256": "0" * 64, **overrides})


def _vector(
    id: str = "inc_v1",
    template: str = "hello",
    severity: str = "medium",
    phase: ScanPhase = ScanPhase.RECONNAISSANCE,
    tags: list[str] | None = None,
) -> AttackVector:
    return AttackVector(
        id=id,
        name=f"Vector {id}",
        category="prompt_injection",
        target_phase=phase,
        description="test vector",
        severity=severity,
        prompts=[AttackPrompt(template=template)],
        tags=tags or [],
    )


def _cap(**overrides: Any) -> AgentCapability:
    data: dict[str, Any] = {
        "id": "search",
        "name": "Search",
        "type": CapabilityType.TOOL,
        "description": "web search",
        "parameters": {"q": "str"},
        "dangerous": False,
    }
    data.update(overrides)
    return AgentCapability(**data)


def _result(**overrides: Any) -> AttackResult:
    data: dict[str, Any] = {
        "vector_id": "inc_v1",
        "vector_name": "Vector inc_v1",
        "category": "prompt_injection",
        "severity": "medium",
        "successful": True,
        "evidence": {"matched": ["x"]},
        "agent_response": "sure",
        "token_usage": TokenUsage(prompt_tokens=3, completion_tokens=4, total_tokens=7),
    }
    data.update(overrides)
    return AttackResult(**data)


class _StubClient:
    def __init__(self, model: str) -> None:
        self.config = LLMConfig(model=model)


class TestKeys:
    def test_campaign_key_is_stable_hex(self) -> None:
        caps = [_cap()]
        key = campaign_key(_ctx(), caps)
        assert len(key) == 64
        int(key, 16)
        assert campaign_key(_ctx(), [_cap()]) == key

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("ziran_version", "9.9.9"),
            ("target_sha256", "1" * 64),
            ("protocol", "a2a"),
            ("framework", "langchain"),
            ("streaming", True),
            ("encoding", ("base64",)),
            ("n_shots", 5),
            ("context_window", 1000),
            ("quality_scoring", True),
            ("judge_model", "m"),
            ("detector", {"disabled": ["llm_judge"]}),
        ],
    )
    def test_every_context_field_changes_key(self, field: str, value: Any) -> None:
        assert campaign_key(_ctx(**{field: value}), []) != campaign_key(_ctx(), [])

    def test_capability_order_does_not_matter(self) -> None:
        caps = [_cap(id="a"), _cap(id="b")]
        assert campaign_key(_ctx(), caps) == campaign_key(_ctx(), list(reversed(caps)))

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("id", "other"),
            ("name", "Other"),
            ("type", CapabilityType.SKILL),
            ("description", "changed"),
            ("parameters", {"q": "int"}),
            ("dangerous", True),
        ],
    )
    def test_every_capability_field_changes_key(self, field: str, value: Any) -> None:
        assert campaign_key(_ctx(), [_cap(**{field: value})]) != campaign_key(_ctx(), [_cap()])

    def test_requires_permission_is_not_hashed(self) -> None:
        assert campaign_key(_ctx(), [_cap(requires_permission=True)]) == campaign_key(
            _ctx(), [_cap()]
        )

    def test_adding_capability_changes_key(self) -> None:
        assert campaign_key(_ctx(), [_cap(), _cap(id="x")]) != campaign_key(_ctx(), [_cap()])

    def test_vector_key_tracks_vector_content(self) -> None:
        ck = campaign_key(_ctx(), [])
        base = vector_key(ck, _vector())
        assert len(base) == 64
        assert vector_key(ck, _vector()) == base
        assert vector_key(ck, _vector(template="changed")) != base
        assert vector_key(ck, _vector(severity="high")) != base
        assert vector_key(ck, _vector(tags=["t"])) != base
        assert vector_key(ck, _vector(id="inc_v2")) != base
        assert vector_key(campaign_key(_ctx(streaming=True), []), _vector()) != base


class TestBuildContext:
    def test_defaults(self) -> None:
        ctx = build_cache_context(
            target_bytes=b"x",
            protocol=None,
            framework=None,
            scanner_config={},
            encoding=None,
            streaming=False,
        )
        assert ctx.ziran_version == ziran.__version__
        assert ctx.target_sha256 == hashlib.sha256(b"x").hexdigest()
        assert ctx.judge_model is None
        assert ctx.detector["thresholds"] == DetectorThresholds().model_dump(mode="json")
        assert ctx.context_window == 200_000
        assert ctx.n_shots is None
        assert ctx.encoding == ()
        assert ctx.quality_scoring is False

    def test_from_scanner_config(self) -> None:
        dc = DetectorConfig(
            disabled={"b", "a"},
            thresholds=DetectorThresholds(hit=0.8),
            judge_clients={"j": _StubClient("jm")},  # type: ignore[dict-item]
            prefilter_client=_StubClient("pm"),  # type: ignore[arg-type]
        )
        ctx = build_cache_context(
            target_bytes=b"x",
            protocol="rest",
            framework="langchain",
            scanner_config={
                "llm_client": _StubClient("m"),
                "quality_scoring": True,
                "n_shots": 5,
                "context_window": 1000,
                "detector_config": dc,
            },
            encoding=("ROT13", "base64"),
            streaming=True,
        )
        assert ctx.judge_model == "m"
        assert ctx.detector["disabled"] == ["a", "b"]
        assert ctx.detector["thresholds"]["hit"] == 0.8
        assert ctx.detector["judge_models"] == {"j": "jm"}
        assert ctx.detector["prefilter_model"] == "pm"
        assert ctx.quality_scoring is True
        assert ctx.n_shots == 5
        assert ctx.context_window == 1000
        assert ctx.encoding == ("base64", "rot13")
        assert (ctx.protocol, ctx.framework, ctx.streaming) == ("rest", "langchain", True)


class TestCacheability:
    def test_successful(self) -> None:
        assert is_cacheable(_result())

    def test_unsuccessful_with_response(self) -> None:
        assert is_cacheable(_result(successful=False))

    def test_error_never_cached(self) -> None:
        assert not is_cacheable(_result(error="boom"))

    def test_swallowed_prompt_errors_never_cached(self) -> None:
        assert not is_cacheable(_result(successful=False, evidence={"prompt_errors": 1}))

    def test_success_with_prompt_errors_cached(self) -> None:
        assert is_cacheable(_result(evidence={"prompt_errors": 1}))

    def test_unsuccessful_without_response(self) -> None:
        assert not is_cacheable(_result(successful=False, agent_response=None))


class TestDisabledReason:
    def test_llm_adaptive(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("x")
        reason = cache_disabled_reason(strategy="LLM-Adaptive", encoding=(), target_path=f)
        assert reason == "the llm-adaptive strategy is not deterministic"

    def test_word_shuffle(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("x")
        reason = cache_disabled_reason(
            strategy="fixed", encoding=("rot13", "word_shuffle"), target_path=f
        )
        assert reason == "word_shuffle encoding is randomised"

    def test_directory_target(self, tmp_path: Path) -> None:
        reason = cache_disabled_reason(strategy="fixed", encoding=(), target_path=tmp_path)
        assert reason == "the target path is not a file"

    def test_ok(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("x")
        assert cache_disabled_reason(strategy="fixed", encoding=("base64",), target_path=f) is None

    def test_scan_cache_refuses_word_shuffle(self) -> None:
        with pytest.raises(ValueError, match="word_shuffle"):
            ScanCache(_ctx(encoding=("word_shuffle",)))


class TestClearCache:
    def test_missing_root(self, tmp_path: Path) -> None:
        assert clear_cache(tmp_path / "nope") == 0

    def test_removes_tree(self, tmp_path: Path) -> None:
        root = tmp_path / "scan_cache"
        (root / "a").mkdir(parents=True)
        (root / "b").mkdir()
        (root / "a" / "1.json").write_text("{}")
        (root / "a" / "2.json").write_text("{}")
        (root / "b" / "3.json").write_text("{}")
        (root / "b" / "3.json.1.tmp").write_text("{}")
        assert clear_cache(root) == 3
        assert not root.exists()


class TestScanCacheFiles:
    async def test_round_trip(self, tmp_path: Path) -> None:
        root = tmp_path / "scan_cache"
        cache = ScanCache(_ctx(), root=root)
        caps = [_cap()]
        stored = _result()
        await cache.record(_vector(), caps, stored)

        path = root / campaign_key(_ctx(), caps) / "inc_v1.json"
        data = json.loads(path.read_text())
        assert data["key"] == vector_key(campaign_key(_ctx(), caps), _vector())
        assert data["result"]["token_usage"]["total_tokens"] == 7

        hit = await cache.lookup(_vector(), caps)
        assert hit is not None
        assert hit.evidence == {"matched": ["x"], "cached": True}
        assert hit.token_usage == TokenUsage()
        assert (
            hit.model_copy(update={"evidence": stored.evidence, "token_usage": stored.token_usage})
            == stored
        )
        assert cache.stats == ScanCacheStats(executed=1, cached=1)

        again = await cache.lookup(_vector(), caps)
        assert again is not None
        assert again.evidence is not hit.evidence
        assert "cached" not in stored.evidence

    async def test_misses(self, tmp_path: Path) -> None:
        cache = ScanCache(_ctx(), root=tmp_path / "scan_cache")
        await cache.record(_vector(), [_cap()], _result())
        assert await cache.lookup(_vector(template="edited"), [_cap()]) is None
        assert await cache.lookup(_vector(), [_cap(dangerous=True)]) is None
        assert await cache.lookup(_vector(id="inc_v9"), [_cap()]) is None
        assert cache.stats.cached == 0

    async def test_corrupt_entry_is_a_miss(self, tmp_path: Path) -> None:
        root = tmp_path / "scan_cache"
        cache = ScanCache(_ctx(), root=root)
        path = root / campaign_key(_ctx(), []) / "inc_v1.json"
        path.parent.mkdir(parents=True)
        path.write_text("{not json")
        assert await cache.lookup(_vector(), []) is None
        path.write_text(json.dumps({"key": "k"}))
        assert await cache.lookup(_vector(), []) is None

    async def test_uncacheable_result_not_written(self, tmp_path: Path) -> None:
        cache = ScanCache(_ctx(), root=tmp_path / "scan_cache")
        await cache.record(_vector(), [], _result(error="boom"))
        assert cache.stats.executed == 1
        assert list(tmp_path.rglob("*.json")) == []

    @pytest.mark.parametrize("bad_id", ["../x", "a" * 129, "a/b"])
    async def test_unsafe_id_never_cached(self, tmp_path: Path, bad_id: str) -> None:
        cache = ScanCache(_ctx(), root=tmp_path / "sub" / "scan_cache")
        vec = _vector(id=bad_id)
        await cache.record(vec, [], _result(vector_id=bad_id))
        assert list(tmp_path.rglob("*.json")) == []
        assert await cache.lookup(vec, []) is None

    async def test_write_failure_is_swallowed(self, tmp_path: Path) -> None:
        root = tmp_path / "scan_cache"
        root.write_text("i am a file")
        cache = ScanCache(_ctx(), root=root)
        await cache.record(_vector(), [], _result())
        assert cache.stats.executed == 1
        assert list(tmp_path.rglob("*.tmp")) == []

    async def test_replace_failure_cleans_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pathlib import Path as _Path

        def _boom(self: _Path, target: Any) -> _Path:
            raise OSError("disk full")

        monkeypatch.setattr(_Path, "replace", _boom)
        cache = ScanCache(_ctx(), root=tmp_path / "scan_cache")
        await cache.record(_vector(), [], _result())
        assert list(tmp_path.rglob("*.tmp")) == []
        assert list(tmp_path.rglob("*.json")) == []

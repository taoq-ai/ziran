"""Opt-in per-vector result cache for incremental scans (spec 049).

The cache is **opt-in only** (``ziran scan --incremental``). A stale cache hides findings: a
remote target can change (model, server-side prompt, tools behind an API) without any change to
the inputs hashed here, so never enable it for release gates or scheduled CI scans.

One JSON file per vector lives at ``<root>/<campaign_key>/<vector_id>.json``. The campaign key
hashes every campaign-wide input that can change a vector's result (:class:`CacheContext`: the
target file bytes, protocol, framework, streaming, encodings, many-shot settings, quality scoring,
judge model, effective detector settings and judge models, ZIRAN version) plus the sorted
discovered capabilities (id, name, type, description, parameters, dangerous). The per-vector key
adds the vector's JSON, so editing a vector re-runs only that vector.

Never cached: results with ``error`` set, unsuccessful results without an agent response
(connection failures surface that way), attack timeouts (no result), vector ids that are not
safe file names, and the ``word_shuffle`` encoding (unseeded shuffle; :class:`ScanCache` refuses
such a context). The CLI also refuses the ``llm-adaptive`` strategy, which is not deterministic:
API users building a :class:`ScanCache` themselves must not combine it with
``LLMAdaptiveStrategy``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.capability import AgentCapability

logger = get_logger(__name__)

DEFAULT_CACHE_DIR: Final = Path(".ziran") / "scan_cache"
UNCACHEABLE_ENCODINGS: Final = frozenset({"word_shuffle"})
_SAFE_ID: Final = re.compile(r"[A-Za-z0-9_.-]{1,128}")  # fullmatch; else never cached
_CAPABILITY_FIELDS: Final = {"id", "name", "type", "description", "parameters", "dangerous"}


class CacheContext(BaseModel):
    """Every campaign-wide input, other than vectors and capabilities, that can change a result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ziran_version: str
    target_sha256: str
    protocol: str | None = None
    framework: str | None = None
    streaming: bool = False
    encoding: tuple[str, ...] = ()
    n_shots: int | None = None
    context_window: int = 200_000
    quality_scoring: bool = False
    judge_model: str | None = None
    detector: dict[str, Any] = Field(default_factory=dict)


class CacheEntry(BaseModel):
    """On-disk shape of ``<root>/<campaign_key>/<vector_id>.json``."""

    key: str
    result: AttackResult


class ScanCacheStats(BaseModel):
    """Per-invocation counts reported in ``metadata["scan_cache"]``."""

    executed: int = 0
    cached: int = 0


def _model(client: Any) -> str | None:
    return str(client.config.model) if client is not None else None


def build_cache_context(
    *,
    target_bytes: bytes,
    protocol: str | None,
    framework: str | None,
    scanner_config: Mapping[str, Any],
    encoding: Sequence[str] | None,
    streaming: bool,
) -> CacheContext:
    """Build the context from the same ``scanner_config`` the scanner reads."""
    import ziran
    from ziran.application.detectors.pipeline import DetectorConfig

    dc = scanner_config.get("detector_config") or DetectorConfig()
    n_shots = scanner_config.get("n_shots")
    return CacheContext(
        ziran_version=ziran.__version__,
        target_sha256=hashlib.sha256(target_bytes).hexdigest(),
        protocol=protocol,
        framework=framework,
        streaming=streaming,
        encoding=tuple(sorted(e.lower() for e in encoding or ())),
        n_shots=int(n_shots) if n_shots is not None else None,
        context_window=int(scanner_config.get("context_window", 200_000)),
        quality_scoring=bool(scanner_config.get("quality_scoring")),
        judge_model=_model(scanner_config.get("llm_client")),
        detector={
            "disabled": sorted(dc.disabled),
            "refusal_matchtype": dc.refusal_matchtype,
            "indicator_matchtype": dc.indicator_matchtype,
            "refusal_languages": (
                list(dc.refusal_languages) if dc.refusal_languages is not None else None
            ),
            "thresholds": (dc.thresholds or DetectorThresholds()).model_dump(mode="json"),
            "judge_models": {n: _model(c) for n, c in sorted(dc.judge_clients.items())},
            "prefilter_model": _model(dc.prefilter_client),
        },
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def campaign_key(context: CacheContext, capabilities: Sequence[AgentCapability]) -> str:
    """Hash of the context plus the discovered capabilities (order-independent)."""
    caps = sorted(
        (c.model_dump(mode="json", include=_CAPABILITY_FIELDS) for c in capabilities),
        key=lambda c: str(c["id"]),
    )
    payload = {"context": context.model_dump(mode="json"), "capabilities": caps}
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def vector_key(campaign_key: str, vector: AttackVector) -> str:
    """Hash of the campaign key plus the vector's full JSON."""
    return _sha256(f"{campaign_key}\n{vector.model_dump_json()}")


def is_cacheable(result: AttackResult) -> bool:
    """Errors, swallowed prompt/turn failures and response-less failures are never
    cached (they would hide findings)."""
    if result.error is not None:
        return False
    if result.successful:
        return True
    return result.agent_response is not None and not result.evidence.get("prompt_errors")


def cache_disabled_reason(
    *, strategy: str, encoding: Sequence[str], target_path: Path
) -> str | None:
    """Why ``--incremental`` cannot be honoured, or ``None``."""
    if strategy.lower() == "llm-adaptive":
        return "the llm-adaptive strategy is not deterministic"
    if any(e.lower() in UNCACHEABLE_ENCODINGS for e in encoding):
        return "word_shuffle encoding is randomised"
    if not target_path.is_file():
        return "the target path is not a file"
    return None


def clear_cache(root: Path = DEFAULT_CACHE_DIR) -> int:
    """Delete *root* recursively; return how many ``*.json`` entries it held."""
    if not root.exists():
        return 0
    removed = sum(1 for _ in root.rglob("*.json"))
    shutil.rmtree(root)
    return removed


class ScanCache:
    """Per-vector result cache. Never raises on cache I/O: problems become misses or skipped
    writes.

    Do not combine with ``LLMAdaptiveStrategy`` (non-deterministic); the CLI refuses it.
    """

    def __init__(self, context: CacheContext, root: Path = DEFAULT_CACHE_DIR) -> None:
        if set(context.encoding) & UNCACHEABLE_ENCODINGS:
            msg = "word_shuffle encoding is randomised and cannot be cached"
            raise ValueError(msg)
        self.context = context
        self.root = root
        self.stats = ScanCacheStats()

    def _entry(
        self, vector: AttackVector, capabilities: Sequence[AgentCapability]
    ) -> tuple[Path, str] | None:
        if not _SAFE_ID.fullmatch(vector.id):
            return None
        ck = campaign_key(self.context, capabilities)
        return self.root / ck / f"{vector.id}.json", vector_key(ck, vector)

    async def lookup(
        self, vector: AttackVector, capabilities: Sequence[AgentCapability]
    ) -> AttackResult | None:
        """Cached result for *vector* (marked ``evidence["cached"]``, zero tokens), or None."""
        entry = self._entry(vector, capabilities)
        if entry is None:
            return None
        path, key = entry
        try:
            text = await asyncio.to_thread(path.read_text, encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError:
            logger.warning("scan_cache_entry_invalid", path=str(path))
            return None
        try:
            stored = CacheEntry.model_validate_json(text)
        except ValidationError:
            logger.warning("scan_cache_entry_invalid", path=str(path))
            return None
        if stored.key != key:
            return None
        self.stats.cached += 1
        result = stored.result
        return result.model_copy(
            update={"token_usage": TokenUsage(), "evidence": {**result.evidence, "cached": True}}
        )

    async def record(
        self,
        vector: AttackVector,
        capabilities: Sequence[AgentCapability],
        result: AttackResult,
    ) -> None:
        """Count an executed vector and store its result when cacheable. Never raises."""
        self.stats.executed += 1
        entry = self._entry(vector, capabilities)
        if entry is None or not is_cacheable(result):
            return
        path, key = entry
        await asyncio.to_thread(
            self._write, path, CacheEntry(key=key, result=result).model_dump_json()
        )

    @staticmethod
    def _write(path: Path, data: str) -> None:
        # Atomic write, same pattern as CheckpointManager.save.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(data, encoding="utf-8")
            tmp.replace(path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            logger.warning("scan_cache_write_failed", path=str(path))

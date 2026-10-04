# Implementation Plan: opt-in incremental scanning (per-vector result cache)

**Branch**: `049-incremental-scan-cache` | **Date**: 2026-10-04 | **Spec**: [spec.md](spec.md)
**Issue**: #288 (release 0.42.0) | **Base**: `develop` @ cff8b7f
**Parallel siblings**: #393 / spec 050 edits `AgentScanner._discover_and_map_capabilities` and the
`--framework` choice list in `main.py`; this plan touches neither. In `scanner.py` this plan edits
`run_campaign` and the `__init__` docstring only. In `main.py` it edits the `scan` options,
signature and body, `_display_results`, and inserts the `cache` group directly after `scan`.

## Summary
A new `ScanCache` (in `ziran/application/agent_scanner/scan_cache.py`) stores one JSON file per
vector under `.ziran/scan_cache/<campaign_key>/<vector_id>.json`. The campaign key hashes every
input other than the vector that can change a vector's result (target file bytes, protocol,
framework, effective detector settings and judge models, quality scoring, streaming, encoding,
many-shot settings, ZIRAN version) plus the sorted discovered capabilities; the per-vector key adds
the vector's JSON. `PhaseExecutor._run_attack` looks the vector up after the spec-047 budget check;
a hit substitutes the cached `AttackResult` (marked `evidence["cached"] = True`, zero tokens) and
then runs the unchanged recording path, so findings, the graph, strategies and accounting behave
as on a fresh run. A miss executes and records. `ziran scan --incremental` builds the cache;
`--no-cache` bypasses it; `ziran cache clear` wipes it. Counts land in `metadata["scan_cache"]` and
the CLI summary. The scanner only forwards the cache object and the capabilities (net-zero lines).

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (cache models), stdlib `hashlib`/`json`/`os`/`re`/`shutil`/`asyncio.to_thread`, Click (scan flags, `cache clear`); reuses `PhaseExecutor`, `ResultBuilder`, the `CheckpointManager.save` atomic-write pattern. No new dependencies.
**Storage**: per-vector JSON files under `.ziran/scan_cache/<campaign_key>/` (working directory; git-ignored; never committed).
**Testing**: pytest, `@pytest.mark.unit` / `@pytest.mark.integration`; `MockAgentAdapter` from
`tests/conftest.py`; custom vector YAMLs in `tmp_path` loaded with
`AttackLibrary(custom_dirs=[...], load_builtin=False)`; the stub executor/library pattern of
`tests/integration/test_partial_phase_resume.py` (with real `AttackVector`s, since keys hash
`model_dump_json()`); Click `CliRunner` with the patching pattern of
`tests/unit/test_cli_main.py::TestScanEnsembleWiring` (`monkeypatch.chdir(tmp_path)`, patched
`load_agent_adapter`). No network, no LLM, no keys.
**Target Platform**: `ziran scan`; `AgentScanner` via `scanner_config["scan_cache"]`.
**Project Type**: single Python package.
**Performance Goals**: per vector one SHA-256 over the context + capabilities (tens of small
dicts) and one over the vector JSON, plus one small file read (hit) or write (miss), off the event
loop via `asyncio.to_thread`.
**Constraints**: `scanner.py` is 750 lines (cap 750, `test_scanner_size.py`): net-zero or negative
diff. Any other `agent_scanner` module <= 400 lines. `attack_executor.py` (395) and
`checkpoint.py` are not touched. mypy strict; line length 100. No prompt/response text in logs.
**Measured today** (`develop` @ cff8b7f, `wc -l`): `scanner.py` 750, `phase_executor.py` 350,
`result_builder.py` 155, `attack_executor.py` 395, `checkpoint.py` 316.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | `scan_cache.py` lives in `application/agent_scanner/` and imports only domain entities (`AttackResult`, `TokenUsage`, `AttackVector`, `AgentCapability`), `DetectorThresholds` (application), Pydantic, stdlib and the logger (as every application module does). File I/O for a local cache in the application layer follows the existing `checkpoint.py` precedent. The driving edge (`main.py`) builds the cache and hands it over through `scanner_config`; the scanner never imports infrastructure. No domain change. |
| II. Type safety | PASS | `CacheContext` (frozen, `extra="forbid"`), `CacheEntry`, `ScanCacheStats` are Pydantic; every function annotated; mypy strict. |
| III. Tests | PASS | Test-first per task: key/context/cacheability unit tests, `ScanCache` file round-trip, `PhaseExecutor` hit/miss/budget-order tests, `ResultBuilder` metadata, scanner integration (edit-one-vector, cached success counted, stop rule), CLI wiring, `cache clear`, display row, and the CLI end-to-end ">= 90% cached" and "--no-cache neither reads nor writes" tests with `MockAgentAdapter`. Existing tests unmodified. |
| IV. Async-first | PASS | `ScanCache.lookup` / `record` are `async` and run file I/O in `asyncio.to_thread`. `clear_cache` is sync and called only from the CLI entry point. |
| V. Extensibility | PASS | No new port and no adapter change; vectors stay YAML. |
| VI. Simplicity | PASS | One module, one class, three small models, four pure functions. Reuses the atomic-write pattern, the existing recording path in `_run_attack`, `metadata` (as `judge_tiers` / `usage`). No TTL, no index file, no per-tool invalidation, no CI auto-detection. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #288 implementer. Names, signatures, config keys, flags, file layout, metadata keys
and display strings MUST NOT change without updating this file.

### 1. `ziran/application/agent_scanner/scan_cache.py` (new, <= 400 lines)

```python
"""Opt-in per-vector result cache for incremental scans (spec 049). ..."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ziran.domain.entities.attack import AttackResult, TokenUsage
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ziran.domain.entities.attack import AttackVector
    from ziran.domain.entities.capability import AgentCapability

DEFAULT_CACHE_DIR: Final = Path(".ziran") / "scan_cache"
UNCACHEABLE_ENCODINGS: Final = frozenset({"word_shuffle"})
_SAFE_ID: Final = re.compile(r"[A-Za-z0-9_.-]{1,128}")   # fullmatch; else never cached
_CAPABILITY_FIELDS: Final = {"id", "name", "type", "description", "parameters", "dangerous"}


class CacheContext(BaseModel):
    """Every campaign-wide input, other than vectors and capabilities, that can change a result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ziran_version: str
    target_sha256: str                        # sha256 hex of the --target / --agent-path bytes
    protocol: str | None = None               # --protocol override (None = from the YAML)
    framework: str | None = None              # --framework (in-process)
    streaming: bool = False
    encoding: tuple[str, ...] = ()            # sorted, lower-case
    n_shots: int | None = None
    context_window: int = 200_000
    quality_scoring: bool = False
    judge_model: str | None = None            # scanner_config["llm_client"].config.model
    detector: dict[str, Any] = Field(default_factory=dict)   # see build_cache_context


class CacheEntry(BaseModel):
    """On-disk shape of ``<root>/<campaign_key>/<vector_id>.json``."""

    key: str                                   # vector_key(...) of the stored result
    result: AttackResult


class ScanCacheStats(BaseModel):
    executed: int = 0                          # vectors run in this invocation (cacheable or not)
    cached: int = 0                            # cache hits substituted in this invocation


def build_cache_context(
    *,
    target_bytes: bytes,
    protocol: str | None,
    framework: str | None,
    scanner_config: Mapping[str, Any],
    encoding: Sequence[str] | None,
    streaming: bool,
) -> CacheContext:
    """Context from the same ``scanner_config`` the scanner reads.

    - ``ziran_version`` = ``ziran.__version__`` (imported inside the function)
    - ``target_sha256`` = ``hashlib.sha256(target_bytes).hexdigest()``
    - ``encoding`` = ``tuple(sorted(e.lower() for e in encoding or ()))``
    - ``n_shots`` = ``scanner_config.get("n_shots")`` (int or None),
      ``context_window`` = ``int(scanner_config.get("context_window", 200_000))``,
      ``quality_scoring`` = ``bool(scanner_config.get("quality_scoring"))``
    - ``judge_model`` = ``scanner_config["llm_client"].config.model`` or None when absent
    - ``detector`` = effective settings of ``scanner_config.get("detector_config")``
      (``DetectorConfig()`` when absent):
      ``{"disabled": sorted(dc.disabled), "refusal_matchtype": ..., "indicator_matchtype": ...,
         "refusal_languages": list(...) | None,
         "thresholds": (dc.thresholds or DetectorThresholds()).model_dump(mode="json"),
         "judge_models": {name: c.config.model for name, c in sorted(dc.judge_clients.items())},
         "prefilter_model": dc.prefilter_client.config.model if dc.prefilter_client else None}``
    """


def campaign_key(context: CacheContext, capabilities: Sequence[AgentCapability]) -> str:
    """sha256 hex of json.dumps({"context": context.model_dump(mode="json"),
    "capabilities": sorted([c.model_dump(mode="json", include=_CAPABILITY_FIELDS) ...],
    key=id)}, sort_keys=True, separators=(",", ":"))."""


def vector_key(campaign_key: str, vector: AttackVector) -> str:
    """sha256 hex of f"{campaign_key}\\n{vector.model_dump_json()}"."""


def is_cacheable(result: AttackResult) -> bool:
    """``result.error is None and (result.successful or result.agent_response is not None)``."""


def cache_disabled_reason(*, strategy: str, encoding: Sequence[str], target_path: Path) -> str | None:
    """Why ``--incremental`` cannot be honoured, or None. Checked in this order:
    ``"the llm-adaptive strategy is not deterministic"`` (strategy.lower() == "llm-adaptive"),
    ``"word_shuffle encoding is randomised"`` (any e.lower() in UNCACHEABLE_ENCODINGS),
    ``"the target path is not a file"`` (not target_path.is_file())."""


def clear_cache(root: Path = DEFAULT_CACHE_DIR) -> int:
    """Delete *root* recursively; return the number of ``*.json`` entry files it held
    (``0`` when *root* does not exist). Sync (CLI entry point only)."""


class ScanCache:
    """Per-vector result cache. Never raises on cache I/O: problems become misses / skipped writes."""

    def __init__(self, context: CacheContext, root: Path = DEFAULT_CACHE_DIR) -> None:
        """Raises ValueError if ``set(context.encoding) & UNCACHEABLE_ENCODINGS``."""
        self.context = context
        self.root = root
        self.stats = ScanCacheStats()

    async def lookup(
        self, vector: AttackVector, capabilities: Sequence[AgentCapability]
    ) -> AttackResult | None:
        """Cached result for *vector*, or None.

        None when the id is unsafe, the file is missing, unreadable or invalid
        (log ``scan_cache_entry_invalid`` with ``path`` only), or ``entry.key`` differs from
        ``vector_key(campaign_key(self.context, capabilities), vector)``. On a hit:
        ``self.stats.cached += 1`` and return ``entry.result.model_copy(update={"token_usage":
        TokenUsage(), "evidence": {**entry.result.evidence, "cached": True}})``.
        The read runs in ``asyncio.to_thread``."""

    async def record(
        self,
        vector: AttackVector,
        capabilities: Sequence[AgentCapability],
        result: AttackResult,
    ) -> None:
        """``self.stats.executed += 1``; then, only if the id is safe and ``is_cacheable(result)``,
        atomically write ``CacheEntry(key=..., result=result).model_dump_json()`` to
        ``self.root / campaign_key / f"{vector.id}.json"`` in ``asyncio.to_thread``:
        ``mkdir(parents=True, exist_ok=True)``; temp file
        ``path.with_name(f"{path.name}.{os.getpid()}.tmp")``; ``tmp.replace(path)``; on
        ``OSError`` unlink the temp file and log ``scan_cache_write_failed`` (``path`` only);
        never raises."""
```

Module docstring states: opt-in only, what is hashed, the never-cache list, and that API users
building a `ScanCache` themselves must not combine it with `LLMAdaptiveStrategy` (the CLI refuses).

### 2. `ziran/application/agent_scanner/phase_executor.py` (edit, stays <= 400 lines)

- `__init__` gains keyword `cache: ScanCache | None = None` (stored as `self._cache`; type
  imported under `TYPE_CHECKING`); docstring line added.
- `execute(...)` gains keyword `capabilities: Sequence[AgentCapability] = ()` (documented: the
  discovered capability set used in cache keys).
- `_run_attack`, inside `async with semaphore:`, after the unchanged budget check and the
  unchanged `ATTACK_START` emit:
  ```python
  result = (
      await self._cache.lookup(attack, capabilities) if self._cache is not None else None
  )
  if result is None:
      metrics.attack_started(phase.value)
      started = perf_counter()
      try:
          async with asyncio.timeout(self._attack_timeout):
              result = await self._attack_executor.execute(attack)
      finally:
          metrics.attack_finished(phase.value)
      metrics.record_attack(... duration_seconds=perf_counter() - started)   # unchanged args
      if self._cache is not None:
          await self._cache.record(attack, capabilities, result)
  ```
  (`metrics.record_attack` moves inside the `if`, so a hit records no attack metrics.) Everything
  from `result.evidence.setdefault("phase", phase.value)` onward is unchanged, including the
  spec-047 target-ledger record (a hit records 0 tokens).

### 3. `ziran/application/agent_scanner/result_builder.py` (edit)

`build(...)` gains keyword `scan_cache: ScanCache | None = None` (type under `TYPE_CHECKING`);
after the `usage` block:
```python
if scan_cache is not None:  # incremental cache counts (spec 049); absent when off
    metadata["scan_cache"] = scan_cache.stats.model_dump()
```

### 4. `ziran/application/agent_scanner/scanner.py` (edit, net <= 0 lines; today 750)

Exactly these edits in `__init__` docstring and `run_campaign`; nothing else:
- `__init__` docstring, config keys list: `+ - ``scan_cache`` (ScanCache): opt-in per-vector
  result cache (spec 049).` (+1)
- `PhaseExecutor(...)` construction: `+ cache=self.config.get("scan_cache"),` (+1)
- `phase_executor.execute(...)` call: `+ capabilities=capabilities,` (+1)
- `result_builder.build(...)` call: `+ scan_cache=self.config.get("scan_cache"),` (+1)
- Replace the 5-line `campaign_tokens = campaign_tokens + TokenUsage(prompt_tokens=...,
  completion_tokens=..., total_tokens=...)` block with
  `campaign_tokens = campaign_tokens + TokenUsage.model_validate(result.token_usage)` (-4;
  identical values: `PhaseResult.token_usage` always holds exactly those three int keys).
Net 0. No new import (the cache is read from `self.config` as `Any`).
`_discover_and_map_capabilities` and `_execute_phase` are not touched (the backward-compatible
`_execute_phase` path runs without a cache).

### 5. `ziran/interfaces/cli/main.py` (edit: `scan`, `_display_results`, new `cache` group)

**Options** (after `--max-cost`, before `--dry-run`):
```python
@click.option(
    "--incremental",
    is_flag=True,
    default=False,
    help="Reuse cached results for vectors whose inputs are unchanged (.ziran/scan_cache/). "
    "Opt-in for fast local iteration; a remote target can change without ZIRAN noticing, so "
    "do not use it for release gates.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass the incremental cache: neither read nor write it (overrides --incremental).",
)
```
Signature: `incremental: bool, no_cache: bool` after `max_cost`.

**Config table** (after the `Budget` row):
```python
if incremental:
    config_table.add_row("Incremental", "off (--no-cache)" if no_cache else "on")
```

**Cache construction** (after the `if max_cost is not None:` warnings block, before
`scanner = AgentScanner(...)`):
```python
if incremental and not no_cache:
    from ziran.application.agent_scanner.scan_cache import (
        ScanCache, build_cache_context, cache_disabled_reason,
    )
    target_path = Path(str(target or agent_path))
    reason = cache_disabled_reason(strategy=strategy, encoding=encoding, target_path=target_path)
    if reason is not None:
        console.print(f"[yellow]Warning:[/yellow] --incremental disabled: {reason}")
    else:
        scanner_config["scan_cache"] = ScanCache(
            build_cache_context(
                target_bytes=target_path.read_bytes(),
                protocol=protocol,
                framework=framework,
                scanner_config=scanner_config,
                encoding=encoding,
                streaming=streaming,
            )
        )
```

**`_display_results`** (after the `Judge Routing` row):
```python
cache = result.metadata.get("scan_cache")
if cache:  # incremental scan counts (spec 049); absent when the cache is off
    summary_table.add_row(
        "Incremental Cache", f"{cache['cached']:,} cached · {cache['executed']:,} executed"
    )
```

**`cache` group** (inserted directly after the `scan` function, before the `discover` banner):
```python
@cli.group(name="cache")
def cache_group() -> None:
    """Manage the incremental scan cache (.ziran/scan_cache/)."""


@cache_group.command(name="clear")
def cache_clear() -> None:
    """Delete every cached scan result under .ziran/scan_cache/."""
    from ziran.application.agent_scanner.scan_cache import DEFAULT_CACHE_DIR, clear_cache

    try:
        removed = clear_cache()
    except OSError as exc:
        raise click.ClickException(f"cannot clear {DEFAULT_CACHE_DIR}: {exc}") from None
    console.print(f"Removed {removed} cached result(s) from {DEFAULT_CACHE_DIR}")
```

### 6. Output shapes

Cache file `.ziran/scan_cache/<64-hex campaign_key>/<vector_id>.json`:
```json
{"key": "<64-hex vector_key>", "result": { ...AttackResult.model_dump(mode="json")... }}
```
Result metadata (only when a `ScanCache` was used):
```json
"scan_cache": {"executed": 1, "cached": 4}
```
A substituted result in `attack_results`: same as stored, plus `evidence.cached: true` and
`token_usage: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}`.
CLI summary row: `Incremental Cache | 4 cached · 1 executed`. Config row: `Incremental | on` or
`Incremental | off (--no-cache)`. `ziran cache clear`: `Removed 4 cached result(s) from
.ziran/scan_cache`.

### 7. Docs and repo files

- `docs/guides/incremental-scanning.md` (new): sections `## When to use it` (local iteration,
  pre-commit), `## When not to use it` (release gates, scheduled CI scans, after changing the
  target's model or server-side prompt: the cache cannot see those; plainly: a stale cache hides
  findings), `## Usage` (`--incremental`, `--no-cache`, `ziran cache clear`, the
  `Incremental Cache` row and `metadata.scan_cache`), `## What invalidates a cached result` (the
  key inputs list of FR-002..FR-004), `## What is never cached` (FR-008 list), `## Pre-commit
  recipe` (a local `repo: local` hook running `ziran scan --incremental ...` on staged agent/vector
  changes), `## CI recipe` (a PR job that MAY opt in with `--incremental` and a cache restored per
  branch, and a release/main job that always runs without it; neither enables it implicitly),
  `## Do not commit the cache` (`.ziran/scan_cache/` holds agent responses; it is git-ignored in
  this repo; add it to your own `.gitignore`), `## Limitations` (Edge Cases of spec.md). No
  timing numbers unless produced by a command actually run (and then labelled as MockAgentAdapter).
- `mkdocs.yml`: `- Incremental Scanning: guides/incremental-scanning.md` right after
  `- Long-Running Campaigns: guides/long-running-campaigns.md`.
- `docs/community/roadmap.md`: the `Incremental / diff scanning` line `- [ ]` -> `- [x]`.
- `.gitignore`: add `.ziran/scan_cache/` (`.ziran` is not ignored today; `.ziran/detectors.yaml`
  and `.ziran/prices.yaml` are meant to be committed).
- `docs/reference/cli.md`: add `--incremental` and `--no-cache` rows to the `ziran scan` option
  table (after `--phase-timeout`), and a `### \`ziran cache clear\`` section (usage, output, link
  to the guide) placed right after the `ziran scan` section.

## Acceptance criteria -> offline proof

| Criterion | Proof (offline) |
|---|---|
| Issue AC1: second run >= 90% skipped (US1) | `tests/integration/test_incremental_scan_cli.py::test_second_run_is_at_least_90_percent_cached`: real `ziran scan` via `CliRunner`, `load_agent_adapter` patched to a fresh non-vulnerable `MockAgentAdapter`, built-in library, phases reconnaissance + trust_building + capability_mapping, `--coverage standard`, `--no-stop-on-critical`, `--incremental`; each run uses its own `--output` dir (`out1`, `out2`: `campaign_id` is second-resolution, so a shared dir could overwrite the report) and the test reads `metadata.scan_cache` from the single `<outN>/campaign_*_report.json`; asserts run 1 `cached == 0`, run 2 ratio >= 0.9, the `Incremental Cache` row in output, same `(vector_id, successful)` set and `total_vulnerabilities`. |
| Issue AC2: edit one vector, only it re-executes (US2.1) | `tests/integration/test_incremental_scan.py::test_editing_one_vector_reexecutes_only_that_vector`: vector dir library, `AgentScanner` with `config={"scan_cache": ScanCache(ctx, root=tmp_path/"scan_cache")}`, run, edit `v3.yaml` template, rebuild library + scanner + cache, run; `metadata["scan_cache"] == {"executed": 1, "cached": 4}`, adapter invocations == [edited template]. |
| Key covers the brief's inputs (US2.2, US2.3) | `tests/unit/application/test_scan_cache.py::TestKeys`: parametrised over every `CacheContext` field and every capability field -> different `campaign_key`; capability order -> same; one prompt edit -> different `vector_key`; plus one integration test adding a capability to the mock between runs -> `cached == 0`. |
| Version bump invalidates everything | `TestKeys` (`ziran_version` field) and `TestBuildContext` (`ziran_version == ziran.__version__`). |
| Cached success counted (US3.1, SC-002) | `test_incremental_scan.py::test_cached_success_counts_in_total_vulnerabilities` (vulnerable mock, `stop_on_critical=False`). |
| Stop rule sees cached result (US3.2) | `test_incremental_scan.py::test_stop_on_critical_honoured_on_cached_run`. |
| Budget check first (US3.3) | `tests/unit/application/test_phase_executor_cache.py::test_budget_skip_does_not_lookup` (stub cache counting calls + exceeded budget stub). |
| Hit = no execution, zero tokens, evidence flag, findings recorded (US1.4, FR-006) | `test_phase_executor_cache.py` hit/miss tests with stub executor and real `AttackVector`s. |
| Never cached (US4.1-4.3, 4.6) | `test_scan_cache.py::TestCacheability` and `TestScanCacheFiles` (error result, no-response failure, unsafe id `../x`: no file anywhere under `tmp_path` except none); `test_phase_executor_cache.py::test_timeout_records_nothing`. |
| word_shuffle / llm-adaptive / directory target (US4.4, 4.5, 4.7) | `TestDisabledReason` + `ScanCache` `ValueError` unit tests; CLI wiring tests assert the warning text and no `scan_cache` key. |
| Flags + `cache clear` (US5.1-5.4) | `tests/unit/test_cli_main.py::TestScanIncrementalWiring` (patched scanner) and `TestCacheClear`; `test_incremental_scan_cli.py::test_no_cache_neither_reads_nor_writes` (real scanner, separate `--output` dirs: seed cache with run 1, snapshot `{path: bytes}` of the tree, run with `--incremental --no-cache`, tree byte-identical, `metadata` has no `scan_cache`, every vector executed per adapter invocations > 0). |
| Cache I/O never fails the scan (US5.5) | `TestScanCacheFiles`: corrupt JSON -> miss; root is an existing *file* -> `record` logs and returns. |
| Counts in metadata and display (FR-010) | `tests/unit/application/test_result_builder_scan_cache.py` (or extend the existing result-builder test file) and `TestDisplayScanCache` in `test_cli_main.py`. |
| Size guards / no sibling clash (SC-003) | `test_scanner_size.py`; `git diff --numstat origin/develop -- ziran/application/agent_scanner/scanner.py`. |
| Speed-up on a real target (SC-005) | Not provable offline; reported as unverified. |

## Project Structure

### Documentation (this feature)
```text
specs/049-incremental-scan-cache/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/application/agent_scanner/scan_cache.py        # new
ziran/application/agent_scanner/phase_executor.py    # edit (cache hook in _run_attack)
ziran/application/agent_scanner/result_builder.py    # edit (metadata["scan_cache"])
ziran/application/agent_scanner/scanner.py           # edit (run_campaign wiring, net 0)
ziran/interfaces/cli/main.py                          # edit (scan flags, display row, cache group)
docs/guides/incremental-scanning.md                   # new
docs/reference/cli.md                                 # edit (scan flags, cache clear)
mkdocs.yml, docs/community/roadmap.md, .gitignore     # edit
tests/unit/application/test_scan_cache.py             # new
tests/unit/application/test_phase_executor_cache.py   # new
tests/unit/application/test_result_builder_scan_cache.py  # new
tests/unit/test_cli_main.py                           # extend (new classes only)
tests/integration/test_incremental_scan.py            # new
tests/integration/test_incremental_scan_cli.py        # new
```
**Structure Decision**: single package, hexagonal layers unchanged.

## Follow-ups (noted, not filed, out of scope)
- Per-tool selective invalidation (re-run only vectors that touch a changed tool) and git-diff
  driven change detection.
- TTL / size management for `.ziran/scan_cache/`.
- A marker on results whose LLM judge timed out, so they can be excluded from caching.
- Hashing the import closure of an in-process agent (today only the `--agent-path` file).
- `action.yml`, web UI, pentest and multi-agent scan support.

## Phases
1. Pure functions and models (`scan_cache.py` keys, context, cacheability, disabled reason,
   `clear_cache`).
2. `ScanCache` file round-trip.
3. `PhaseExecutor` hook + `ResultBuilder` metadata.
4. Scanner wiring (net-zero) + integration tests.
5. CLI flags, display row, `cache clear`, CLI end-to-end tests.
6. Docs, `.gitignore`, roadmap, mkdocs; gates.

## Complexity Tracking
None.

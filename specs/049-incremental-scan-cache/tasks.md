# Tasks: opt-in incremental scanning (per-vector result cache)

Base: `origin/develop` @ cff8b7f. Work on branch `049-incremental-scan-cache`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys. New unit tests carry
`@pytest.mark.unit`, new integration tests `@pytest.mark.integration`; tests added to existing
files follow that file's conventions. Names, config keys, flags, file layout, metadata keys and
display strings are exactly those in [plan.md §Public contract](plan.md#public-contract). Existing
tests MUST NOT be modified: they are the "cache off = unchanged" regression net
(`test_scanner_size.py` included).

Shared test helpers (defined in the test file that first needs them; copied, not a new module):
- `_ctx(**overrides) -> CacheContext`: `CacheContext(ziran_version="0.0.0", target_sha256="0" *
  64, **overrides)`.
- `_vector(id="inc_v1", template="hello", severity="medium", phase=ScanPhase.RECONNAISSANCE)`: a
  real `AttackVector` with one `AttackPrompt(template=template)`.
- `_write_vector_dir(path)`: writes `v1.yaml` .. `v5.yaml` (ids `inc_v1` .. `inc_v5`, phase
  `reconnaissance`, `inc_v1` severity `critical`, others `medium`, one single-tactic prompt each)
  and `t1.yaml` (`inc_t1`, `trust_building`, `medium`) in the library's YAML format (copy the
  layout of an existing custom-attacks test fixture).

## Phase 1 - Keys, context, cacheability (FR-002, FR-003, FR-004, FR-008)

- [ ] T001 [P] Failing tests `tests/unit/application/test_scan_cache.py`:
      - `TestKeys`: `campaign_key` is 64-hex and stable for equal inputs; parametrised over every
        `CacheContext` field (`ziran_version`, `target_sha256`, `protocol`, `framework`,
        `streaming`, `encoding`, `n_shots`, `context_window`, `quality_scoring`, `judge_model`,
        `detector`) -> changing one changes the key; capability list reversed -> same key;
        parametrised over `id`, `name`, `type`, `description`, `parameters`, `dangerous` ->
        changing one changes the key; `requires_permission` change -> same key (not hashed);
        adding a capability changes the key; `vector_key` changes when one prompt template, the
        severity or the tags change, and differs for two vectors under one campaign key.
      - `TestBuildContext`: with `scanner_config={}` -> `ziran_version == ziran.__version__`,
        `target_sha256 == hashlib.sha256(b"x").hexdigest()` for `target_bytes=b"x"`,
        `judge_model is None`, `detector["thresholds"] == DetectorThresholds().model_dump(
        mode="json")`, `context_window == 200_000`, `n_shots is None`; with a stub client
        (`config.model == "m"`, a real `LLMConfig`) as `llm_client`, `quality_scoring: True`,
        `n_shots: 5`, `context_window: 1000`, and a `DetectorConfig(disabled={"b", "a"},
        thresholds=DetectorThresholds(hit=0.8), judge_clients={"j": stub("jm")},
        prefilter_client=stub("pm"))` -> `judge_model == "m"`, `detector["disabled"] == ["a",
        "b"]`, `detector["thresholds"]["hit"] == 0.8`, `detector["judge_models"] == {"j": "jm"}`,
        `detector["prefilter_model"] == "pm"`, `quality_scoring is True`; `encoding=("ROT13",
        "base64")` -> `("base64", "rot13")`.
      - `TestCacheability`: `is_cacheable` True for a successful result and for an unsuccessful
        result with an `agent_response`; False with `error` set (even if successful), and for an
        unsuccessful result with `agent_response=None`.
      - `TestDisabledReason`: `llm-adaptive` (any case) -> the strategy reason; `("rot13",
        "word_shuffle")` -> the encoding reason; a directory path -> the target reason; a file
        with `fixed` and `("base64",)` -> `None`; `ScanCache(_ctx(encoding=("word_shuffle",)))`
        raises `ValueError`.
      - `TestClearCache`: missing root -> `0`; a root with two campaign dirs holding three
        `*.json` files and one `*.tmp` -> returns `3` and the root no longer exists.
      Confirm they fail (`ModuleNotFoundError`).
- [ ] T002 Implement the models, `DEFAULT_CACHE_DIR`, `UNCACHEABLE_ENCODINGS`, `build_cache_context`,
      `campaign_key`, `vector_key`, `is_cacheable`, `cache_disabled_reason`, `clear_cache` in
      `ziran/application/agent_scanner/scan_cache.py` per plan §1 (module docstring: opt-in only,
      what is hashed, never-cache list, llm-adaptive warning for API users). T001 passes; mypy
      strict clean.

## Phase 2 - ScanCache file round-trip (FR-005, US4.6, US5.5)

- [ ] T003 [P] Failing tests, extend `test_scan_cache.py` with `TestScanCacheFiles`
      (`root=tmp_path / "scan_cache"`, `pytest.mark.asyncio` or the repo's async test style):
      - `record` then `lookup` of the same vector and capabilities -> result equal to the stored
        one except `evidence["cached"] is True` and `token_usage == TokenUsage()`; the stored
        file is `root / campaign_key(ctx, caps) / "inc_v1.json"`, parses as
        `{"key": vector_key(...), "result": {...}}`, and the original's token usage is kept on
        disk; `stats == ScanCacheStats(executed=1, cached=1)`.
      - Edited vector (same id, new template) -> `lookup` is `None`, `stats.cached` unchanged.
      - Different capabilities -> `None`; missing file -> `None`.
      - Corrupt JSON in the entry file -> `None`, no exception.
      - Uncacheable result (`error` set) -> `record` counts `executed` and writes no file.
      - Unsafe id `"../x"` and a 129-character id -> `record` writes nothing anywhere under
        `tmp_path` (assert `list(tmp_path.rglob("*.json")) == []`), `lookup` is `None`.
      - `root` is an existing regular file -> `record` returns normally (failed write logged),
        no `*.tmp` left behind.
      - The stored `AttackResult` is not mutated by the hit copy (`evidence` has no `cached` key
        on a second lookup's source; two lookups return independent dicts).
- [ ] T004 Implement `ScanCache.__init__`, `lookup`, `record` per plan §1 (`asyncio.to_thread`,
      PID-suffixed temp + `replace`, warnings `scan_cache_entry_invalid` /
      `scan_cache_write_failed` with `path` only). T003 passes; file stays <= 400 lines.

## Phase 3 - PhaseExecutor hook and result metadata (FR-006, FR-007, FR-009, FR-010)

- [ ] T005 [P] Failing tests `tests/unit/application/test_phase_executor_cache.py` (stub
      executor/library pattern of `tests/integration/test_partial_phase_resume.py`, but returning
      real `AttackVector`s from `_vector(...)`; real `AttackKnowledgeGraph`; real `ScanCache` on
      `tmp_path` unless a stub is needed):
      - Miss then hit: first `PhaseExecutor(..., cache=cache).execute(..., capabilities=caps)`
        runs the executor for every vector and writes entries; a second executor instance with
        the same cache runs the stub executor zero times, `attack_results` hold
        `evidence["cached"] is True` results with zero `token_usage`, `PhaseResult.token_usage`
        totals are 0, `tested_vector_ids` contains every id, and `ATTACK_COMPLETE` events are
        emitted once per vector.
      - A cached successful result appears in `PhaseResult.vulnerabilities_found` and
        `artifacts`, and the graph has its vulnerability node.
      - `budget` stub whose `exceeded()` is True -> a stub cache's `lookup` is never awaited and
        the executor is never called (budget check first).
      - Executor raising `TimeoutError` (attack timeout) -> `record` never called, no file.
      - `cache=None` (default) -> behaviour identical to today (executor called for each vector,
        no `cached` evidence key).
      - With a budget whose ledger is present, a hit records 0 target tokens.
- [ ] T006 [P] Failing tests `tests/unit/application/test_result_builder_scan_cache.py`:
      `ResultBuilder.build(..., scan_cache=cache)` with `cache.stats = ScanCacheStats(executed=1,
      cached=4)` -> `metadata["scan_cache"] == {"executed": 1, "cached": 4}`; without it -> key
      absent.
- [ ] T007 Implement plan §2 (`phase_executor.py`) and §3 (`result_builder.py`). T005, T006
      pass; both modules <= 400 lines; mypy clean; all existing phase-executor tests pass.

## Phase 4 - Scanner wiring and integration (FR-013, US1.4, US2, US3)

- [ ] T008 Failing tests `tests/integration/test_incremental_scan.py` (`MockAgentAdapter` from
      `tests.conftest`, `_write_vector_dir`, library rebuilt per run with
      `AttackLibrary(custom_dirs=[dir], load_builtin=False)`, a fresh adapter, scanner and
      `ScanCache(_ctx(), root=tmp_path / "scan_cache")` per run, `max_concurrent_attacks=1`):
      - `test_editing_one_vector_reexecutes_only_that_vector` (US2.1).
      - `test_capability_change_invalidates_all` (US2.2 end-to-end: run 2's mock has one extra
        capability -> `{"executed": 5, "cached": 0}`).
      - `test_cached_success_counts_in_total_vulnerabilities` (US3.1, vulnerable mock,
        `stop_on_critical=False`, `phases=[RECONNAISSANCE]`).
      - `test_stop_on_critical_honoured_on_cached_run` (US3.2).
      - `test_cached_results_zero_tokens` (US1.4: run 2 `result.token_usage["total_tokens"] ==
        0`, every attack result has `evidence["cached"] is True`).
      - `test_no_cache_key_is_unchanged_behaviour` (no `scan_cache` key -> no
        `metadata["scan_cache"]`, executor runs every vector, a pre-seeded cache root unchanged).
- [ ] T009 Implement plan §4 in `scanner.py`: exactly the listed five edits. Verify
      `wc -l ziran/application/agent_scanner/scanner.py` <= 750 and
      `git diff --numstat origin/develop -- ziran/application/agent_scanner/scanner.py` shows
      deletions >= insertions; `_discover_and_map_capabilities`, `attack_executor.py` and
      `checkpoint.py` untouched. T008, `tests/unit/application/test_scanner_size.py` and
      `tests/unit/test_scanner.py` pass.

## Phase 5 - CLI (FR-010, FR-011, FR-012, US1, US4.4-4.7, US5)

- [ ] T010 Failing tests, extend `tests/unit/test_cli_main.py` with new classes only (patching
      pattern of `TestScanEnsembleWiring`: `monkeypatch.chdir(tmp_path)`, `agent.py` written,
      patched `load_agent_adapter`, `asyncio`, `AgentScanner`):
      - `TestScanIncrementalWiring`: no flag -> `"scan_cache" not in config`; `--incremental` ->
        `config["scan_cache"]` is a `ScanCache` with `root == DEFAULT_CACHE_DIR`,
        `context.target_sha256 == sha256(Path("agent.py").read_bytes())`,
        `context.framework == "langchain"`, output has `Incremental` and `on`; `--incremental
        --no-cache` -> no key, output has `off (--no-cache)`; `--no-cache` alone -> no key, no
        `Incremental` row; `--incremental --encoding word_shuffle` -> no key and the warning
        `--incremental disabled: word_shuffle encoding is randomised`; `--incremental --strategy
        llm-adaptive` (with `--llm-provider` and a patched `create_llm_client` returning a stub
        with a real `LLMConfig`, and patched `build_strategy`) -> no key and the llm-adaptive
        warning; `--agent-path` a directory with `--incremental` -> no key and the target warning;
        `.ziran/scan_cache` not created in any of these.
      - `TestCacheClear`: seeded `.ziran/scan_cache/<k>/a.json`, `b.json` -> `ziran cache clear`
        exit 0, output `Removed 2 cached result(s) from .ziran/scan_cache`, dir gone; no dir ->
        `Removed 0 cached result(s)`; `ziran cache --help` lists `clear`.
      - `TestDisplayScanCache`: `_display_results` on a result with `metadata["scan_cache"] =
        {"executed": 1, "cached": 1234}` prints `Incremental Cache` and `1,234 cached · 1
        executed`; without the key the row is absent; the JSON dump
        (`ziran/interfaces/cli/reports.py::_dump_campaign_result`) contains
        `metadata.scan_cache`.
- [ ] T011 Failing tests `tests/integration/test_incremental_scan_cli.py` (real scanner, real
      built-in library, real `asyncio`; only `ziran.interfaces.cli.main.load_agent_adapter`
      patched to return a fresh non-vulnerable `MockAgentAdapter` per call and recorded; args
      `scan --framework langchain --agent-path agent.py --phases reconnaissance --phases
      trust_building --phases capability_mapping --coverage standard --no-stop-on-critical
      --concurrency 1`; a separate `--output` per run):
      - `test_second_run_is_at_least_90_percent_cached` (US1.1-1.3): run 1 `--incremental`
        (`cached == 0`, `executed == len(attack_results)`, entry files exist), run 2
        `--incremental` (`cached / (cached + executed) >= 0.9`, output has `Incremental Cache`,
        same `total_vulnerabilities` and `(vector_id, successful)` set; if `executed == 0` the
        run-2 adapter's `invocations` is empty).
      - `test_no_cache_neither_reads_nor_writes` (US5.3): run 1 `--incremental`; snapshot
        `{p: p.read_bytes() for p in Path(".ziran/scan_cache").rglob("*") if p.is_file()}`; run 2
        `--incremental --no-cache` -> exit 0, snapshot identical, report `metadata` has no
        `scan_cache`, run-2 adapter `invocations` non-empty.
- [ ] T012 Implement plan §5 in `ziran/interfaces/cli/main.py` (options, signature, config row,
      cache construction, `_display_results` row, `cache` group after `scan`; nothing else, in
      particular not the `--framework` choice list). T010, T011 pass; every existing
      `test_cli_main.py` test passes unmodified.

## Phase 6 - Docs, repo files, gates (FR-015, FR-016)

- [ ] T013 `docs/guides/incremental-scanning.md` per plan §7 (plain staleness warning, "not for
      release gates", "do not commit `.ziran/scan_cache/`", pre-commit and CI recipes with the
      release job running without the cache, limitations). Any number in it must come from a
      command actually run (label MockAgentAdapter timings as such) or be omitted.
- [ ] T014 `mkdocs.yml` nav entry after `Long-Running Campaigns`; `docs/reference/cli.md` scan rows
      and `ziran cache clear` section; `docs/community/roadmap.md` #288 line `[x]`; `.gitignore`
      `.ziran/scan_cache/`. `uv run mkdocs build --strict` if the docs toolchain is installed
      (report if it is not; do not claim it).
- [ ] T015 Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). `git diff --stat origin/develop` shows no `uv.lock`,
      no `attack_executor.py`, no `checkpoint.py`, no `CHANGELOG.md`, and `scanner.py` with
      deletions >= insertions. PR body (against `develop`): the commands run and their real
      output, the integration test cached ratio actually observed, SC-005 unverified.

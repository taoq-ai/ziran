# Feature Specification: opt-in incremental scanning (per-vector result cache)

**Feature Branch**: `049-incremental-scan-cache`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #288 (release 0.42.0, "faster scans, truer graphs" batch).
**Base**: `develop` @ cff8b7f (0.41.0 released; #399 / spec 047 budget check already in
`PhaseExecutor._run_attack`).
**Siblings (parallel, separate worktrees)**: #393 / spec 050 (langgraph-native scanning: edits
`AgentScanner._discover_and_map_capabilities`, `knowledge_graph/graph.py`, the `--framework`
choices in `main.py`), #73 / spec 051 (`http_adapter._probe_discover`, a `TargetConfig` /
`RetryConfig` field), #368 / spec 052 (tests only). Shared files: `scanner.py` (this feature edits
`run_campaign` only, net-zero lines, never `_discover_and_map_capabilities`) and
`ziran/interfaces/cli/main.py` (this feature edits the `scan` options/signature/body,
`_display_results`, and adds a `cache` command group right after `scan`).
**Scope**: `ziran scan` (and `AgentScanner` used through `scanner_config`) only.
**Input**: every `ziran scan` re-runs the full vector set. A developer iterating on one tool wants
"just re-test what changed" in seconds, which would make ZIRAN usable as a pre-commit hook. The
issue asks for `ziran scan --incremental`, a per-vector cache keyed on the vector, the target
config, the discovered tools and the ZIRAN version, `--no-cache`, `ziran cache clear`, executed vs
cached counts in the output, and a guide with pre-commit and CI recipes.

## User Scenarios & Testing *(mandatory)*

Shared fixtures for the scenarios below (all offline, no network, no LLM, no keys):
- **Mock target**: `MockAgentAdapter` from `tests/conftest.py` (non-vulnerable: responds
  `"I cannot help with that request."`; vulnerable: `vulnerable=True`, deterministic side-effect
  hit). A fresh adapter is built per run so its response cycle restarts.
- **Vector dir**: a `tmp_path` directory with five single-vector YAML files (`v1.yaml` ..
  `v5.yaml`, ids `inc_v1` .. `inc_v5`, phase `reconnaissance`, one `single`-tactic prompt each;
  `inc_v1` has severity `critical`, the others `medium`) plus `t1.yaml` (id `inc_t1`, phase
  `trust_building`, severity `medium`), loaded with
  `AttackLibrary(custom_dirs=[dir], load_builtin=False)`.
- **Cache root**: `tmp_path / "scan_cache"` (unit/integration) or `.ziran/scan_cache` under a
  `monkeypatch.chdir(tmp_path)` working directory (CLI).

### User Story 1 - A second unchanged scan reuses cached results (Priority: P1)

A developer runs `ziran scan --incremental` twice with nothing changed. The second run executes
(almost) nothing against the target and reports how many results came from the cache.

**Why this priority**: issue acceptance criterion 1 ("run scan twice, second run shows >= 90%
skipped"); the reason the feature exists.

**Independent Test**: `ziran scan --framework langchain --agent-path agent.py --phases
reconnaissance --phases trust_building --phases capability_mapping --coverage standard
--no-stop-on-critical --incremental --output out` through Click's `CliRunner`, with
`ziran.interfaces.cli.main.load_agent_adapter` patched to return a fresh non-vulnerable
`MockAgentAdapter` (the scanner, the attack library and `asyncio` are real).

**Acceptance Scenarios**:
1. **Given** an empty cache, **When** the first run completes, **Then** exit code is `0`, the
   result JSON's `metadata.scan_cache.cached == 0`, `metadata.scan_cache.executed` equals the
   number of attack results, and `.ziran/scan_cache/<campaign_key>/` holds one `<vector_id>.json`
   per cacheable result.
2. **Given** the cache from run 1 and nothing changed, **When** the second run completes, **Then**
   `cached / (cached + executed) >= 0.9`, the summary table shows an `Incremental Cache` row
   `"<cached> cached · <executed> executed"`, and when `executed == 0` the run-2 adapter's
   `invocations` list is empty.
3. **Given** the two runs, **Then** run 2's `total_vulnerabilities`, the set of
   `(vector_id, successful)` pairs in `attack_results`, and each phase's `vulnerabilities_found`
   equal run 1's.
4. **Given** a cached result is reused, **Then** its `evidence["cached"] is True` and its
   `token_usage` is all zeros, so `CampaignResult.token_usage` and the spec-047 `target` ledger
   entry count only tokens actually spent in this run.

### User Story 2 - Editing one vector re-executes only that vector (Priority: P1)

**Why this priority**: issue acceptance criterion 2.

**Independent Test**: `AgentScanner(MockAgentAdapter(...), attack_library=<vector dir library>,
config={"scan_cache": ScanCache(ctx, root=tmp_path / "scan_cache")})`,
`run_campaign(phases=[ScanPhase.RECONNAISSANCE], max_concurrent_attacks=1)`, run twice with a new
scanner, a new `ScanCache` (same `ctx`, same root) and a new library each time.

**Acceptance Scenarios**:
1. **Given** run 1 executed all five vectors, **When** `v3.yaml`'s prompt template is edited and
   run 2 runs, **Then** `metadata["scan_cache"] == {"executed": 1, "cached": 4}` and the adapter's
   `invocations` contain only the edited template.
2. **Given** an unchanged library, **When** the `CacheContext` changes in any single field (target
   bytes, protocol, framework, detector settings, judge model, quality scoring, streaming,
   encoding list, `n_shots`, `context_window`, ZIRAN version) or the discovered capability set
   changes (a capability added/removed, or its `name`, `type`, `description`, `parameters` or
   `dangerous` changed), **Then** every vector misses (unit-proven on the key functions, and once
   end-to-end for a capability change).
3. **Given** the capability list in a different order, **Then** the keys are identical.

### User Story 3 - Cached findings count exactly like fresh findings (Priority: P1)

**Why this priority**: the brief's correctness rule: a cached success must still be a finding.
Reusing the checkpoint `tested_vector_ids` exclude path would drop cached successes from
`PhaseResult.vulnerabilities_found` and undercount `total_vulnerabilities`; this feature must not.

**Independent Test**: as US2 with `MockAgentAdapter(vulnerable=True)` and
`run_campaign(..., stop_on_critical=False)`.

**Acceptance Scenarios**:
1. **Given** run 1 found `V > 0` vulnerabilities, **When** run 2 is served fully from the cache,
   **Then** `run2.total_vulnerabilities == V`, each `PhaseResult.vulnerabilities_found` equals run
   1's, `metadata["finding_sources"]["detector"] == V`, the knowledge graph of run 2 has a
   vulnerability node for each cached success, and `metadata["scan_cache"]["cached"] == 5`.
2. **Given** `phases=[RECONNAISSANCE, TRUST_BUILDING]` and the default `stop_on_critical=True`,
   **When** run 1 stops after reconnaissance on the critical `inc_v1` finding and run 2 is served
   from the cache, **Then** run 2 also has exactly one phase executed, `inc_t1` is in neither
   run's `attack_results`, and run 2 reports `{"executed": 0, "cached": 5}` (strategy stop rules
   see the cached result).
3. **Given** a spec-047 token cap is reached, **Then** the budget check still runs first: a
   skipped vector is neither looked up nor executed (cache hits never bypass the cap logic).

### User Story 4 - Results that must never be cached (Priority: P1)

**Why this priority**: a stale or bogus cache entry is a silent false negative.

**Acceptance Scenarios**:
1. **Given** a result with `error` set, **Then** it is not written (it re-executes next run).
2. **Given** an unsuccessful result with `agent_response is None` (no valid response came back:
   every prompt failed, timed out per prompt, hit a connection error, or the many-shot vector was
   skipped for the context budget), **Then** it is not written.
3. **Given** an attack that timed out (`attack_timeout`) or raised, **Then** nothing is written
   (no result exists).
4. **Given** `--encoding word_shuffle` (alone or with other encodings), **Then** `ziran scan
   --incremental` prints `Warning: --incremental disabled: word_shuffle encoding is randomised`
   and runs without a cache; `ScanCache(...)` with `word_shuffle` in its context raises
   `ValueError`.
5. **Given** `--strategy llm-adaptive`, **Then** `ziran scan --incremental` prints `Warning:
   --incremental disabled: the llm-adaptive strategy is not deterministic` and runs without a
   cache.
6. **Given** a vector id that is not a safe file name (anything outside `[A-Za-z0-9_.-]`, or longer
   than 128 characters, e.g. `../x`), **Then** it is never looked up or written (it always
   executes) and no file is created outside the cache root.
7. **Given** `--agent-path` pointing at a directory, **Then** `--incremental` is disabled with
   `Warning: --incremental disabled: the target path is not a file`.

### User Story 5 - Flags and cache management (Priority: P1)

**Acceptance Scenarios**:
1. **Given** no cache flag, **Then** `scanner_config` has no `scan_cache` key and the campaign is
   exactly as today (no `metadata["scan_cache"]`, no `Incremental Cache` row).
2. **Given** `--incremental`, **Then** `scanner_config["scan_cache"]` is a `ScanCache` rooted at
   `.ziran/scan_cache` whose `context.target_sha256` is the SHA-256 of the `--target` YAML or
   `--agent-path` file bytes, and the "Scan Configuration" table shows `Incremental` = `on`.
3. **Given** `--incremental --no-cache` (or `--no-cache` alone), **Then** no `ScanCache` is built,
   the cache is neither read nor written: a pre-seeded `.ziran/scan_cache` tree is byte-identical
   after a real (unpatched-scanner) run, every vector executes, and `Incremental` shows
   `off (--no-cache)` when `--incremental` was given.
4. **Given** a populated `.ziran/scan_cache`, **When** `ziran cache clear` runs, **Then** exit
   code `0`, output `Removed <n> cached result(s) from .ziran/scan_cache`, and the directory no
   longer exists. **Given** no cache directory, **Then** exit `0` and `Removed 0 cached result(s)
   ...`.
5. **Given** a cache I/O failure (unreadable or corrupt entry file, unwritable root), **Then** the
   scan still completes: a corrupt entry is a miss, a failed write is logged
   (`scan_cache_write_failed`, path only, no response text) and skipped.

### Edge Cases
- **Staleness is the user's risk**: a remote target can change behaviour (model swap, server-side
  prompt change, data change) without any change to the files ZIRAN hashes. The cache cannot see
  that. This is why the cache is opt-in only, is never auto-enabled (CI or otherwise), and the
  guide says not to use it for release gates.
- **What is hashed for the target**: the `--target` YAML bytes (not environment variables it
  references via `!env`), or the `--agent-path` file bytes (not modules it imports). Documented.
- **Editable installs**: the ZIRAN version is the installed distribution version; editing ZIRAN's
  own source in a dev checkout does not invalidate the cache. Documented (`ziran cache clear`).
- **Judge degraded verdicts**: when an LLM judge call times out the detector pipeline falls back
  silently (no marker on the result), so such a verdict can be cached. Documented; remedy is
  `ziran cache clear` or `--no-cache`. A marker would touch the detector pipeline: follow-up.
- **Counts**: `executed` counts vectors actually run in this invocation (cacheable or not);
  `cached` counts cache hits. Budget-skipped vectors are in neither. After `--resume`, vectors
  restored from the checkpoint are in neither (they were excluded by the checkpoint path as today).
- **Concurrent scans sharing a cache root**: each entry is written atomically (temp file in the
  same directory, PID-suffixed, then `os.replace`); last writer wins; readers never see a partial
  file.
- **Growth**: every distinct campaign key gets its own directory; nothing is pruned
  (TTL / size management is out of scope). `ziran cache clear` wipes everything.
- **Sensitive content**: entries hold agent responses and prompts exactly like the result JSON in
  `--output`; the guide says to treat `.ziran/scan_cache/` like scan results and never commit it,
  and `.gitignore` gains `.ziran/scan_cache/` (`.ziran` itself is not ignored because
  `.ziran/detectors.yaml` and `.ziran/prices.yaml` are meant to be committed).
- **Progress events**: a hit still emits `ATTACK_START` and `ATTACK_COMPLETE` (progress bars
  complete), but no attack metrics (`attack_started`, `attack_finished`, `record_attack`), since
  nothing ran.
- **Cache directory is relative to the working directory** (like `.ziran/detectors.yaml` and
  `.ziran/prices.yaml`).

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (module)**: new `ziran/application/agent_scanner/scan_cache.py` (<= 400 lines) holds
  the models, key functions, `ScanCache` and `clear_cache` exactly as in plan.md §Public contract.
- **FR-002 (campaign key)**: `campaign_key(context, capabilities)` = SHA-256 hex of the canonical
  JSON (`sort_keys=True`, compact separators) of `{"context": context.model_dump(mode="json"),
  "capabilities": [...]}`, where capabilities are sorted by `id` and reduced to `id`, `name`,
  `type`, `description`, `parameters`, `dangerous` (`model_dump(mode="json")`).
- **FR-003 (vector key)**: `vector_key(campaign_key, vector)` = SHA-256 hex of
  `campaign_key + "\n" + vector.model_dump_json()`.
- **FR-004 (context)**: `CacheContext` carries `ziran_version` (`ziran.__version__`),
  `target_sha256`, `protocol`, `framework`, `streaming`, `encoding` (sorted, lower-case),
  `n_shots`, `context_window`, `quality_scoring`, `judge_model` and `detector` (the effective
  detector settings: `disabled`, both match types, `refusal_languages`, the full
  `DetectorThresholds` dump including `ensemble`, `prefilter` and `semantic`, the ensemble judge
  client models and the prefilter client model). `build_cache_context(...)` derives it from the
  same `scanner_config` dict the scanner reads.
- **FR-005 (storage)**: one file per vector at `<root>/<campaign_key>/<vector_id>.json` holding
  `CacheEntry(key=vector_key, result=AttackResult)` serialised with `model_dump_json()` (the
  `result` is `AttackResult.model_dump(mode="json")`). Written atomically (temp + `os.replace`,
  the `CheckpointManager.save` pattern); file I/O runs in `asyncio.to_thread`.
- **FR-006 (hit)**: on a hit `PhaseExecutor._run_attack` substitutes the cached `AttackResult`
  (a copy with `evidence["cached"] = True` and `token_usage = TokenUsage()`) for the executor
  call and then follows the unchanged recording path (attack_results, `tested_vector_ids`, phase
  tokens, spec-047 target ledger, vulnerabilities, artifacts, knowledge graph, checkpoint hook,
  `ATTACK_COMPLETE`), so strategies, `ResultBuilder` accounting and gates behave as on a fresh run.
- **FR-007 (miss)**: on a miss the vector executes as today and the result is passed to
  `ScanCache.record`, which counts it as executed and writes it only when `is_cacheable(result)`.
- **FR-008 (never cached)**: `is_cacheable(result)` is `result.error is None and (result.successful
  or result.agent_response is not None)`; `word_shuffle` encoding and the `llm-adaptive`
  strategy disable the cache (CLI) and `ScanCache` rejects a `word_shuffle` context; unsafe vector
  ids are never cached.
- **FR-009 (budget order)**: the spec-047 budget check stays first inside the concurrency slot;
  lookup happens only after it passes.
- **FR-010 (counts)**: `metadata["scan_cache"] = {"executed": int, "cached": int}` when a cache was
  used (absent otherwise); `_display_results` shows `Incremental Cache` =
  `"<cached:,> cached · <executed:,> executed"` when present.
- **FR-011 (CLI)**: `ziran scan --incremental` (flag, default off) and `--no-cache` (flag; wins
  over `--incremental`; bypass, neither read nor write); `Incremental` row in the "Scan
  Configuration" table when `--incremental` is given; warnings of US4.4, US4.5, US4.7; new command
  group `ziran cache` with `ziran cache clear`.
- **FR-012 (opt-in only)**: the cache is never enabled implicitly (no CI auto-detection, no env
  var, no config-file switch).
- **FR-013 (scanner wiring)**: `scanner.py` passes `self.config.get("scan_cache")` to
  `PhaseExecutor` and `ResultBuilder.build`, and `capabilities` to `PhaseExecutor.execute`; the
  diff is net-zero or negative; `_discover_and_map_capabilities` is not touched.
- **FR-014 (size guards)**: `scanner.py` <= 750 lines; `scan_cache.py`, `phase_executor.py`,
  `result_builder.py` <= 400 lines; `attack_executor.py` and `checkpoint.py` not touched.
- **FR-015 (docs)**: `docs/guides/incremental-scanning.md` (what is hashed, what is never cached,
  flags, counts, `ziran cache clear`, the staleness warning in plain words, "do not use for
  release gates", "do not commit `.ziran/scan_cache/`", a pre-commit recipe and a CI recipe in
  which the cache is explicitly opt-in and the release gate runs without it, limitations from
  Edge Cases); `mkdocs.yml` nav entry `Incremental Scanning: guides/incremental-scanning.md`
  right after `Long-Running Campaigns`; `docs/reference/cli.md` lists the two flags and
  `ziran cache clear`; `docs/community/roadmap.md` line for #288 ticked `[x]`; `.gitignore` gains
  `.ziran/scan_cache/`.
- **FR-016 (no regressions)**: every existing test passes unmodified; no new dependency;
  `uv.lock` unchanged.

### Assumptions (recorded, most conservative reading)
- The issue's "or auto-enabled in CI contexts" is rejected (release planner): a stale cache is a
  silent false negative, so the cache is opt-in only and the docs say so.
- The issue's "discovered tool schemas" is the sorted capability set. `description` is included in
  addition to the brief's `id/name/type/parameters/dangerous`: an LLM agent reads tool
  descriptions, so a description change can change behaviour; including it can only cause extra
  re-execution, never a stale hit.
- `streaming` and `quality_scoring` are added to the key for the same reason (they change how
  results are produced or what they contain). Coverage, phases, concurrency, timeouts, the
  strategy (other than `llm-adaptive`), the output dir and the defence profile are not in the key:
  they select or schedule vectors, or post-process results, but do not change a vector's result.
- The issue's "only caches deterministic vectors" is implemented as the never-cache list (FR-008);
  LLM judging itself is not treated as non-deterministic (the judge model and all detector
  settings are in the key, as the brief specifies).
- `--no-cache` without `--incremental` is accepted and is a no-op (the cache is off by default).
- `ziran cache clear` takes no options; it always clears `.ziran/scan_cache` under the working
  directory (the only location the CLI uses).
- Counts are per invocation (not restored from a checkpoint).

### Key Entities
- **CacheContext** (frozen, `extra="forbid"`): everything except the vector and the capabilities
  that can change a vector's result.
- **CacheEntry**: `key` + `result` (one file per vector).
- **ScanCacheStats**: `executed`, `cached`.
- **ScanCache**: root + context + stats; async `lookup` / `record`.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US5 pass as tests with `MockAgentAdapter`, stub executors and Click
  `CliRunner` (no network, no LLM, no keys). The issue's two acceptance tests are named:
  `test_second_run_is_at_least_90_percent_cached` and
  `test_editing_one_vector_reexecutes_only_that_vector`.
- **SC-002**: a cached success is counted in `total_vulnerabilities` (US3.1 test).
- **SC-003**: `tests/unit/application/test_scanner_size.py` passes; `git diff --numstat
  origin/develop -- ziran/application/agent_scanner/scanner.py` shows deletions >= insertions;
  `_discover_and_map_capabilities` unchanged; `attack_executor.py` and `checkpoint.py` absent
  from the diff.
- **SC-004**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-005 (unverified offline)**: wall-clock speed-up on a real remote target and the real
  staleness rate are not measurable here (no live target, no keys); not claimed. Any timing in
  the docs or PR must come from a command actually run against `MockAgentAdapter`, labelled as
  such.

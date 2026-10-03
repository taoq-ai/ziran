# Tasks: per-campaign token budget and cost accounting with a hard cap

Base: `origin/develop` @ 7d4132e. Work on branch `047-token-budget-cost-cap`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys. New unit tests carry
`@pytest.mark.unit`; tests added to existing files follow that file's conventions. Names, stage
names, config keys, flags, metadata keys and display strings are exactly those in
[plan.md §Public contract](plan.md#public-contract). Existing tests MUST NOT be modified: they are
the "no cap = unchanged" regression net (`test_scanner_size.py` included).

Shared test helpers (defined in the test file that first needs them; copied, not a new module):
- `_UsageStub(BaseLLMClient)`: `LLMConfig(model=<model>)`, `complete` increments `self.calls` and
  returns `LLMResponse(content=<content>, prompt_tokens=<p>, completion_tokens=<c>)`; defaults
  `model="m"`, `content='{"verdict":"failure","confidence":0.95}'`, `p=100`, `c=20`; optional
  `raises=`.
- `PRICES = PriceTable(models={"m": ModelPrice(input_per_mtok=2.50, output_per_mtok=10.00)})`
  (one default stub call = 0.00045 USD).

## Phase 1 - Usage models, ledger, pricing, budget (FR-003, FR-004, FR-006)

- [ ] T001 [P] Failing tests `tests/unit/test_usage.py`:
      - `TestLedger`: three `record("judge", "m", 100, 20)` -> one entry, `calls == 3`,
        `prompt_tokens == 300`, `completion_tokens == 60`, `total_tokens == 360`; a
        `record(..., estimated=True)` increments `estimated_calls`; distinct `(stage, model)`
        pairs make distinct entries; `total_tokens()` sums all entries (target included);
        `entries()` returns copies with `cost_usd is None` (mutating them does not change the
        ledger); `restore(entries)` on a fresh ledger reproduces the totals and on a non-empty one
        adds to them; `summary()` is sorted by `STAGES` order then model.
      - `TestPricing`: `PRICES.cost("m", 100, 20) == 0.00045`; three calls -> entry
        `cost_usd == 0.00135`, `abs(ledger.total_cost() - 3 * 0.00045) < 1e-9`; rounding to 6
        decimals (`cost("m", 1, 0) == round(2.5e-6, 6)`); `price_for("openai/m")` falls back to
        `"m"`, exact name wins over the suffix; unknown model -> `cost(...) is None`, entry
        `cost_usd is None` (not `0`); `target` entries are never priced even when the table has a
        price for their model key; `total_cost()` is `None` when no entry is priced; `PriceTable`
        rejects unknown keys, negative prices and `version: 2`.
      - `TestBudget`: `UsageBudget(max_tokens=0)` / `max_cost_usd=0` / `-1` raise
        `ValidationError`; no limits -> `exceeded()` always False; `max_tokens=360` is False at 359
        and True at 360 (at the cap counts); `max_cost_usd=0.0004` True after one priced call;
        unpriced calls never trip the cost cap; the `campaign_budget_exceeded` warning is logged
        once across repeated `exceeded()` calls (caplog / structlog capture as the repo's logging
        tests do) and carries no prompt text; `from_config({})` gives a fresh ledger and no limits;
        `from_config({"usage_ledger": L, "max_campaign_tokens": 5, "max_cost": 1.0})` uses `L`;
        `from_config({"max_campaign_tokens": 0})` raises `ValidationError`; `summary()` carries
        the limits, `unpriced_tokens` and `total_cost_usd`.
      Confirm they fail (`ModuleNotFoundError`).
- [ ] T002 Implement `ziran/application/usage.py` per plan §1 (module docstring: purpose, stages,
      cooperative cap). T001 passes; mypy strict clean.

## Phase 2 - Decorator, heuristic, price table (FR-001, FR-002, FR-005)

- [ ] T003 [P] Failing tests `tests/unit/test_usage_tracking_client.py`:
      - `TestDecorator`: wrapping `_UsageStub()` with stage `"judge"` records one `judge`/`m`
        entry per call with 100/20; the returned object `is` the stub's response; `messages`,
        `temperature`, `max_tokens` and extra kwargs reach the stub unchanged; `config` is the
        inner client's; an inner exception propagates and records nothing; `health_check`
        delegates and records nothing; a call through `stream_complete` (base fallback) is recorded
        once; `track(None, ledger, "judge") is None`.
      - `TestHeuristic`: zero-usage stub, messages totalling 400 chars, reply of 80 chars ->
        100 / 20, `estimated_calls == 1`; `prompt_tokens=50, completion_tokens=0` with an 80-char
        reply -> 50 / 20, estimated; both non-zero -> `estimated_calls == 0`.
      - `TestPriceTable`: `load_price_table(tmp_path / "absent.yaml")` returns the shipped table
        and it validates; `DEFAULT_PRICE_TABLE.is_file()`; every model key in the shipped YAML has
        a `# source: http` comment on its line (text check; vacuous when `models: {}`); an
        override with `models: {m: {...}}` is merged over the shipped table; override with bad
        YAML / unknown key / negative price raises `PriceTableError` whose message starts
        `"invalid price table "` and names the path.
      Confirm they fail.
- [ ] T004 Implement `ziran/infrastructure/llm/usage_tracking_client.py` per plan §2 and
      `ziran/infrastructure/llm/prices.yaml` per plan §3. Prices: add an entry only if copied from
      the provider's public pricing page in this session, with `# source: <URL> (retrieved
      <date>)`; otherwise ship `models: {}`. Never invent a price. T003 passes; mypy clean.

## Phase 3 - Phase executor, checkpoint, result metadata (FR-008..FR-011)

- [ ] T005 [P] Failing tests `tests/unit/application/test_phase_executor_budget.py` (stub
      executor/library/graph pattern of `test_phase_executor_checkpoint.py`; the stub executor
      returns results with `TokenUsage(prompt_tokens=7, completion_tokens=3, total_tokens=10)`
      and records into the ledger a fixed `record("judge", "m", 100, 20)` per execution to drive
      the budget):
      - no budget -> all 5 vectors run (today's behaviour);
      - budget with `max_tokens=1`, `max_concurrent=1` -> exactly 1 vector executed,
        `tested_vector_ids == {"v0"}`, `budget.interrupted_phase == phase`;
      - same with `max_concurrent=3` -> between 1 and 3 vectors executed;
      - budget reached exactly by the last vector -> all run, `interrupted_phase is None`;
      - target stage: the ledger has a `target`/`unknown` entry with `calls ==` vectors executed
        and `prompt_tokens == 7 * n`, `completion_tokens == 3 * n`.
- [ ] T006 [P] Failing tests, extend `tests/unit/application/test_checkpoint.py`
      (`TestUsagePersistence`): `build_checkpoint(..., usage=[UsageEntry(...)])` round-trips
      through `save`/`load`; a checkpoint JSON without `usage` loads with `usage == []`;
      `IncrementalCheckpointer(..., budget=b)` with `b.interrupted_phase = ScanPhase.X` and
      `phase_results` containing X writes `completed_phases` without X and `remaining_phases`
      starting with `X.value`, and `usage` equal to `b.ledger.entries()`; without a budget the
      written file is as today (`usage == []`); `load_resume_state(mgr, phases, ledger)` restores
      the ledger totals, and without `ledger` behaves as today.
- [ ] T007 [P] Failing tests, extend `tests/unit/application/test_result_builder.py`:
      `build(..., usage=budget)` sets `metadata["usage"] == budget.summary().model_dump(mode=
      "json")`; with a hit budget also `metadata["status"] == "budget_exceeded"`; without a hit no
      `status`; without `usage` neither key (today's output).
- [ ] T008 Implement plan §4 (`phase_executor.py`), §5 (`checkpoint.py`), §6
      (`result_builder.py`). T005-T007 pass; each module stays <= 400 lines; mypy clean.

## Phase 4 - Scanner wiring and end-to-end cap (FR-007, FR-008, FR-013)

- [ ] T009 Failing tests, extend `tests/unit/test_scanner.py` (`MockAgentAdapter` from
      conftest, `shared_attack_library`, one phase that loads > 1 vector, asserted in the test;
      stub judge wrapped as `UsageTrackingClient(_UsageStub(), ledger, stage="judge")` passed as
      `config["llm_client"]`, `ledger = UsageLedger(PRICES)` as `config["usage_ledger"]`):
      - `TestUsageAccounting`: US1.1, US1.2 (entries, costs, `token_usage` unchanged, total =
        sum of entries).
      - `TestBudgetCap`: US2.1 (`max_campaign_tokens: 1`, concurrency 1, `CheckpointManager
        (tmp_path)`: one attack result, `status`, partial phase present, checkpoint file exists);
        US2.2 (concurrency 3 -> 1..3 results); US2.3 (`max_cost: 0.0004`); US2.4 (stub model
        `"other"` not priced, `max_cost` set -> completes, no `status`); US2.5 (resume with a new
        scanner, no cap: executed vector not re-invoked, checked via `MockAgentAdapter.
        invocations`; remaining vectors run; restored ledger totals included; no `status`;
        checkpoint removed); US2.6 (cap reached exactly at a phase's last vector, two phases; the
        cap is the first phase's ledger total measured by an uncapped calibration run with the
        same deterministic stubs:
        second phase not started, checkpoint `completed_phases` holds the first, resume runs only
        the second); US2.7 (no cap: no `status`, checkpoint cleaned); US2.8 (`utility_tasks` with
        a cap hit: post-attack measurement not run, no `metadata["utility"]`); US5.5
        (`AgentScanner(config={"max_campaign_tokens": 0})` raises `ValidationError`).
- [ ] T010 Implement plan §7 in `scanner.py`: exactly the listed edits and the six comment-line
      deletions. Verify `wc -l ziran/application/agent_scanner/scanner.py` <= 750 and
      `git diff --numstat origin/develop -- ziran/application/agent_scanner/scanner.py` shows
      deletions >= insertions; `attack_executor.py` untouched. T009 and
      `tests/unit/application/test_scanner_size.py` pass.

## Phase 5 - CLI (FR-012)

- [ ] T011 Failing tests, extend `tests/unit/test_cli_main.py` (patching pattern of
      `TestScanEnsembleWiring`: `monkeypatch.chdir(tmp_path)`, patched `create_llm_client` returning `_UsageStub(model=kw["model"])`
      (a real `LLMConfig`, so price lookups see a string model),
      `load_agent_adapter`, `asyncio`, `AgentScanner`; also patch
      `ziran.interfaces.cli.main.build_strategy` to capture its client):
      - `TestScanBudgetWiring`: US5.1 (flags -> `scanner_config` keys, `usage_ledger` is a
        `UsageLedger`, `Budget` row text `"50,000 tokens · $2.5"`, judge client is
        `UsageTrackingClient` with stage `judge`, strategy client stage `strategy`; with a
        `.ziran/detectors.yaml` enabling ensemble (member with `model`) and prefilter, the
        `judge_clients` values are tracked `ensemble` and `prefilter_client` tracked `prefilter`);
        no flags -> keys present with `None` limits and the raw `llm_client` absent when no
        provider; US5.2 (`--max-campaign-tokens 0`, `--max-cost 0`, `--max-cost -1` -> exit 2);
        US5.3 (`--max-cost 1` with an unpriced model prints the per-model warning once; without an
        LLM client prints the cannot-trigger warning); US4.3 (invalid `.ziran/prices.yaml` ->
        exit 1, message starts `"invalid price table"`, scanner not constructed); US5.4 (the
        patched run returns a result with `metadata["status"] = "budget_exceeded"` -> output has
        the `Status` row text and the `"Budget reached; checkpoint kept in"` hint, exit 0).
      - `TestDisplayUsage`: `_display_results` with a `metadata["usage"]` holding one priced and
        one unpriced entry (priced: `total_tokens=120`, `cost_usd=0.0123`) prints
        `Usage · judge · m`, `"120 tokens · $0.0123"`, `cost n/a`, `All-Stage Tokens`, `Estimated Cost` with the `tokens unpriced`
        suffix; without `usage` none of these rows appear (US1.4); the JSON dump of that result
        (`ziran/interfaces/cli/reports.py::_dump_campaign_result`) contains `metadata.usage`
        (US1.3).
- [ ] T012 Implement plan §8 in `ziran/interfaces/cli/main.py` (`scan` options, signature, body,
      `_display_results` rows only; `_scan_detector_config` and the `ci` command untouched). T011
      passes; every existing `test_cli_main.py` test passes unmodified.

## Phase 6 - Docs, packaging, gates (FR-014, FR-015, SC-005)

- [ ] T013 `docs/guides/long-running-campaigns.md`: add `## Token budget and cost cap` before
      `## Notes`: the two flags with an example, the five stages and what each covers, where the
      numbers appear (summary rows, `metadata.usage`, `metadata.status`), the price table and the
      `.ziran/prices.yaml` override format, `null` cost for unknown models and the target, the
      chars/4 heuristic, the cooperative cap (overshoot up to `--concurrency` in-flight attacks),
      resuming with `--resume` and a higher or no cap, and the Edge-Case limitations (strategy
      stage records nothing until the `asyncio.run` bug is fixed, ensemble members without
      `model` count as `judge`, timeouts and embeddings not recorded). No numbers that were not
      produced by a command actually run.
- [ ] T014 Packaging check: `uv build --wheel --out-dir <scratch>` then list the wheel and confirm
      `ziran/infrastructure/llm/prices.yaml` is present (SC-005). If the build cannot run here,
      report SC-005 as unverified in the PR; do not claim it.
- [ ] T015 Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). `git diff --stat origin/develop` shows no `uv.lock`,
      no `attack_executor.py`, no `CHANGELOG.md`. PR body: the commands run and their real output,
      the price-table status (empty or cited entries), SC-006 unverified.

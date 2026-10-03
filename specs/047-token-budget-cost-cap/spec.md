# Feature Specification: per-campaign token budget and cost accounting with a hard cap

**Feature Branch**: `047-token-budget-cost-cap`
**Created**: 2026-10-03
**Status**: Active
**Issue**: #399 (release 0.41.0, "gates you can leave on" batch).
**Base**: `develop` @ 7d4132e (#396 ensemble, #397 semantic tier and #398 prefilter merged).
**Siblings (parallel, separate worktrees)**: #447 / spec 045 (`mcp_metadata_analyzer.py` only),
#395 / spec 046 (`ziran ci` in `ziran/interfaces/cli/main.py`), #217 / spec 048
(`html_report.py` only). The only shared file is `ziran/interfaces/cli/main.py`: this feature
edits the `scan` command and `_display_results` only.
**Scope**: `ziran scan` (and `AgentScanner` used through `scanner_config`) only.
**Input**: a campaign makes LLM calls in the judge stage (single judge, #396 ensemble members,
#398 prefilter), in the LLM-adaptive strategy, and invokes the target agent. Today only the
target's tokens are summed (`CampaignResult.token_usage`, read by the promptfoo provider, the web
`run_manager`, the checkpoint and the CLI). Nothing reports the judge's tokens, nothing estimates
cost, and nothing can stop a campaign that overruns a budget.

## User Scenarios & Testing *(mandatory)*

Shared fixtures for the scenarios below (all offline):
- **Stub client**: a `BaseLLMClient` with `config.model == "m"` whose `complete` returns
  `LLMResponse(content='{"verdict":"failure","confidence":0.95}', prompt_tokens=100,
  completion_tokens=20)` and counts its calls.
- **Zero-usage stub**: same, but returns `prompt_tokens=0, completion_tokens=0`.
- **Test price table**: `PriceTable(models={"m": ModelPrice(input_per_mtok=2.50,
  output_per_mtok=10.00)})`. One stub call therefore costs
  `100 * 2.50 / 1e6 + 20 * 10.00 / 1e6 = 0.00045` USD.

### User Story 1 - Every campaign reports tokens and cost by stage and model (Priority: P1)

An operator runs `ziran scan` with an LLM judge. At the end the CLI summary and the result JSON
show, for each (stage, model) pair, the calls, prompt/completion/total tokens and the estimated
cost, plus a campaign total.

**Why this priority**: issue acceptance criterion 1; the basis for budgeting and for comparing
campaign cost across releases.

**Independent Test**: `AgentScanner` with `MockAgentAdapter`, the stub client wrapped as
`UsageTrackingClient(stub, ledger, stage="judge")`, a `UsageLedger` built with the test price
table, one phase.

**Acceptance Scenarios**:
1. **Given** the setup above, **When** `run_campaign` completes, **Then**
   `result.metadata["usage"]["entries"]` contains a `judge` / `m` entry whose `calls` equals the
   stub's call count, `prompt_tokens == 100 * calls`, `completion_tokens == 20 * calls`,
   `total_tokens == 120 * calls` and `cost_usd == round(0.00045 * calls, 6)`; and a `target` /
   `unknown` entry whose `total_tokens` equals `result.token_usage["total_tokens"]` and whose
   `cost_usd` is `null`.
2. **Given** the same result, **Then** `result.token_usage` is exactly what it is today (target
   tokens only; no judge tokens added), and `metadata["usage"]["total_tokens"]` is the sum of all
   entries' `total_tokens`.
3. **Given** the result is saved by `ziran scan`, **Then** the JSON report contains
   `metadata.usage` with the same content (the report already serialises `metadata`).
4. **Given** `_display_results` on that result, **Then** the "Campaign Summary" table has one
   `Usage · <stage> · <model>` row per entry (`"<total_tokens:,> tokens · $<cost:.4f>"`, or
   `"... · cost n/a"` when `cost_usd` is null), an `All-Stage Tokens` row and an `Estimated Cost`
   row. **Given** a result without `metadata["usage"]` (an old JSON passed to `ziran report`),
   **Then** none of these rows appear and the table is as today.

### User Story 2 - A low budget stops the campaign cleanly with partial results (Priority: P1)

An operator sets `--max-campaign-tokens` or `--max-cost`. When the cap is reached the scanner
stops scheduling new attacks, lets in-flight attacks finish, and returns what it has, marked
`budget_exceeded`. The checkpoint is kept so `--resume` (with a higher or no cap) continues.

**Why this priority**: issue acceptance criterion 2; the reason the feature exists.

**Independent Test**: same as US1 plus `scanner_config` keys `max_campaign_tokens` /
`max_cost`, a `CheckpointManager(tmp_path)`, and the shared attack library restricted to one
phase that loads more than one vector.

**Acceptance Scenarios**:
1. **Given** `max_campaign_tokens: 1` and `max_concurrent_attacks=1`, **When** `run_campaign`
   runs, **Then** exactly one vector is executed (the budget is 0 before the first vector and
   >= 120 after it), `result.metadata["status"] == "budget_exceeded"`, `result.attack_results`
   has 1 entry, `result.phases_executed` holds the partial phase, and the checkpoint file still
   exists.
2. **Given** `max_campaign_tokens: 1` and `max_concurrent_attacks=3`, **Then** at most 3 vectors
   are executed (cooperative cap: overshoot is bounded by the attacks already in flight).
3. **Given** `max_cost: 0.0004` (just under one stub call) and `max_concurrent_attacks=1`,
   **Then** the run stops after the first vector with `status == "budget_exceeded"`.
4. **Given** `max_cost` set and the stub's model absent from the price table, **Then** the cost
   cap never triggers (unpriced calls do not count towards it) and the run completes normally;
   `ziran scan` prints a warning naming each tracked model that has no price (US5.3).
5. **Given** the checkpoint from US2.1, **When** a new `AgentScanner` (no cap) resumes from it,
   **Then** the previously executed vector is not re-run, the remaining vectors of the
   interrupted phase run, the restored ledger totals are included in the new
   `metadata["usage"]`, `metadata` has no `status` key, and the checkpoint is removed.
6. **Given** the budget is reached exactly by the last vector of a phase (no vector skipped),
   **Then** the phase is recorded as completed in the checkpoint, the next phase is not started,
   and resume starts at the next phase.
7. **Given** no cap, **Then** the campaign behaves as today: no `status` key, checkpoint cleaned
   up, same attack results.
8. **Given** a cap is hit, **Then** the post-attack utility measurement (`--utility-tasks`) is
   skipped (no further target invocations after the stop).

### User Story 3 - Cost matches tokens x price; unknown usage and unknown models are honest (Priority: P1)

**Why this priority**: issue acceptance criterion 3 and the "never report 0 for unknown" rule.

**Independent Test**: `UsageLedger`, `PriceTable` and `UsageTrackingClient` unit tests with the
stubs; no scanner needed.

**Acceptance Scenarios**:
1. **Given** three recorded stub calls, **Then** the `judge`/`m` entry's `cost_usd` is
   `0.00135` and `abs(total_cost_usd - 3 * 0.00045) < 1e-9`.
2. **Given** the zero-usage stub and messages whose contents total 400 characters and a reply of
   80 characters, **When** one call goes through the decorator, **Then** the entry records
   `prompt_tokens == 100`, `completion_tokens == 20` (`many_shot.estimate_tokens`, chars // 4)
   and `estimated_calls == 1`. A response reporting `prompt_tokens=50, completion_tokens=0` with an
   80-character reply records `50` and `20` (the heuristic fills only the zero field) and counts
   as estimated.
3. **Given** a model not in the price table, **Then** its entry's `cost_usd` is `null` (never
   `0`), its tokens are counted in `unpriced_tokens`, and when no entry has a known cost
   `total_cost_usd` is `null`.
4. **Given** model `"openai/gpt-x"` and a table containing `"gpt-x"`, **Then** the price of
   `"gpt-x"` is used (exact name first, then the part after the last `/`).
5. **Given** the inner client raises, **Then** the exception propagates unchanged and nothing is
   recorded.
6. **Given** any call, **Then** the decorator returns the inner `LLMResponse` object unchanged
   and forwards `messages`, `temperature`, `max_tokens` and `**kwargs` unchanged.

### User Story 4 - Price table shipped with the package and overridable by the operator (Priority: P1)

**Acceptance Scenarios**:
1. **Given** the installed package, **Then** `ziran/infrastructure/llm/prices.yaml` exists, loads
   through `load_price_table()` and validates. Every model entry in it carries a comment citing
   the provider's public pricing URL and the retrieval date; if no pricing page could be retrieved
   when it was written, it ships as `models: {}`.
2. **Given** `.ziran/prices.yaml` in the working directory, **Then** its `models` entries are
   merged over the shipped ones (operator wins per model) and used for every cost.
3. **Given** an invalid override (bad YAML, unknown key, negative price), **Then** `ziran scan`
   exits `1` with `"invalid price table .ziran/prices.yaml: ..."` before the campaign starts.

### User Story 5 - Configured from the scan CLI or scanner_config (Priority: P1)

**Acceptance Scenarios**:
1. **Given** `ziran scan ... --llm-provider litellm --max-campaign-tokens 50000 --max-cost 2.5`,
   **Then** `AgentScanner` receives `scanner_config` with `max_campaign_tokens == 50000`,
   `max_cost == 2.5` and `usage_ledger` (a `UsageLedger`), the "Scan Configuration" table shows a
   `Budget` row, `scanner_config["llm_client"]` is a `UsageTrackingClient` with stage `judge`,
   the client passed to `build_strategy` is a `UsageTrackingClient` with stage `strategy`, and
   (when the detector config enables them) every `judge_clients` value is tracked with stage
   `ensemble` and `prefilter_client` with stage `prefilter`.
2. **Given** `--max-campaign-tokens 0` or `--max-cost 0` or a negative value, **Then** click
   rejects it (exit `2`).
3. **Given** `--max-cost` and a tracked model with no price, **Then** a yellow warning
   `"no price for model '<m>': its calls do not count towards --max-cost"` is printed once per
   model; **given** `--max-cost` and no LLM client at all, **then** a warning says the cost cap
   cannot trigger (only the unpriced target stage is tracked).
4. **Given** a result with `metadata["status"] == "budget_exceeded"`, **Then** the summary table
   shows a `Status` row `BUDGET EXCEEDED (partial results)` and `scan` prints
   `"Budget reached; checkpoint kept in <output>. Re-run with --resume and a higher cap to
   continue."`; exit code `0`.
5. **Given** `AgentScanner(config={"max_campaign_tokens": 0})` (API use), **Then** construction
   raises `pydantic.ValidationError`.

### Edge Cases
- **Cooperative cap**: the check runs before each vector (after it acquires a concurrency slot)
  and before each phase. Attacks already running finish, and all their judge calls are recorded,
  so the final totals can exceed the cap by up to `--concurrency` attacks' worth of tokens. A
  single multi-prompt vector is never cut midway.
- **At the cap counts as reached** (`total >= cap`).
- **Skipped vectors** are not added to `tested_vector_ids` and emit no `ATTACK_COMPLETE`, so the
  resumed run executes them.
- **Interrupted phase in the checkpoint**: a phase in which at least one vector was skipped is
  written to the checkpoint as not completed (it stays in `remaining_phases`), so resume re-enters
  it and skips the already-tested vectors (the spec-031 partial-phase path). Its partial
  `PhaseResult` is still in this run's `CampaignResult.phases_executed`. As today for crash
  resume, the resumed run's `PhaseResult` for that phase lists only the vulnerabilities found
  after the resume (the earlier ones remain in `attack_results`); this is inherited, not new.
- **Resuming with the same cap** stops again immediately before the next phase, returns the
  restored results with `status: budget_exceeded`, and leaves the checkpoint untouched.
- **Target stage**: tokens come from `AttackResult.token_usage` (what the adapter reports, as
  today); adapters that report nothing contribute 0. The target is the operator's own agent, so it
  is never priced (`cost_usd: null`, model key `"unknown"`). `calls` for the target entry counts
  completed vectors, not individual invocations. No heuristic is applied to the target
  (`attack_executor.py` is at its size cap and the per-invocation text is not available to the
  phase executor).
- **Strategy stage**: `LLMAdaptiveStrategy` calls `asyncio.run(...)` inside the running loop, which
  raises before the client is awaited, so the strategy stage records nothing until that bug is
  fixed. Follow-up, out of scope (not filed by this spec).
- **Ensemble members without their own `model`** reuse the judge client, so their calls are
  recorded under stage `judge`; stage `ensemble` covers members with their own `model`.
- **Calls cancelled by a timeout** (judge timeout, attack timeout) or failing in the provider are
  not recorded: no usage is known for them.
- **Concurrency**: the ledger is mutated only on the event-loop thread with no `await` between
  read and write, so no lock is needed.
- **Streaming**: `UsageTrackingClient` does not override `stream_complete`; the base fallback
  routes through `complete()`, so a streamed call is recorded. No internal caller streams.
- **Not tracked**: semantic-tier embedding calls, utility-task invocations, pentest, web UI runs'
  CLI summary (the web runner still gets `metadata["usage"]` with the target stage).

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (decorator)**: `UsageTrackingClient(inner, ledger, *, stage)` in
  `ziran/infrastructure/llm/usage_tracking_client.py` implements `BaseLLMClient`, delegates
  `complete` and `health_check`, and after each successful `complete` records one call into the
  ledger under its fixed `stage` and `inner.config.model`. Call sites do not change.
- **FR-002 (heuristic fallback)**: a zero `prompt_tokens` is replaced by
  `estimate_tokens("".join(m.get("content", "") for m in messages))`, a zero `completion_tokens`
  by `estimate_tokens(response.content)` (`ziran.application.attacks.many_shot.estimate_tokens`);
  the call counts in `estimated_calls` when either was replaced. Totals are always
  `prompt + completion` (the reported `total_tokens` is ignored).
- **FR-003 (ledger)**: `UsageLedger` in `ziran/application/usage.py` accumulates per
  `(stage, model)`: `calls`, `prompt_tokens`, `completion_tokens`, `total_tokens`,
  `estimated_calls`; exposes totals, a checkpoint snapshot and restore.
- **FR-004 (pricing)**: cost per entry = `prompt * input_per_mtok / 1e6 + completion *
  output_per_mtok / 1e6`, rounded to 6 decimals; `null` when the model has no price or the stage
  is `target`. Lookup: exact model string, then the part after the last `/`. Campaign
  `total_cost_usd` = rounded sum of known entry costs, `null` if none is known.
- **FR-005 (price table)**: `ziran/infrastructure/llm/prices.yaml` (shipped in the wheel) with
  `version: 1`, `currency: USD`, `models: {<model>: {input_per_mtok, output_per_mtok}}`; operator
  override `.ziran/prices.yaml` merged per model; invalid file -> `PriceTableError`. Prices are
  only ever copied from the provider's public page with a citing comment; otherwise `models: {}`.
- **FR-006 (budget)**: `CampaignBudget` (ledger + `UsageBudget(max_tokens, max_cost_usd)`);
  `exceeded()` is true when `ledger.total_tokens() >= max_tokens` or
  `ledger.total_cost() >= max_cost_usd` (known costs only); logs `campaign_budget_exceeded`
  (limit, totals; no prompt text) once.
- **FR-007 (scanner_config keys)**: `usage_ledger` (`UsageLedger`, optional: a fresh unpriced
  ledger otherwise), `max_campaign_tokens` (int > 0, optional), `max_cost` (float USD > 0,
  optional), validated at `AgentScanner` construction.
- **FR-008 (enforcement)**: `PhaseExecutor` checks `budget.exceeded()` at the start of each
  vector, inside the concurrency slot, before executing; on a hit it skips the vector and marks
  the phase interrupted. `AgentScanner.run_campaign` checks before each phase (loop condition).
  On a hit: no further phases or vectors are scheduled, the partial `CampaignResult` is built,
  `metadata["status"] = "budget_exceeded"`, post-attack utility is skipped, and the checkpoint is
  not cleaned up.
- **FR-009 (target stage)**: `PhaseExecutor` records each completed vector's
  `AttackResult.token_usage` as stage `target`, model `"unknown"`, under the existing result
  lock.
- **FR-010 (checkpoint)**: `CampaignCheckpoint.usage: list[UsageEntry]` (default `[]`, so old
  checkpoints load). The incremental checkpointer writes the ledger snapshot, omits the
  interrupted phase from `completed_phases` and keeps it in `remaining_phases`;
  `load_resume_state` restores the ledger.
- **FR-011 (result)**: `metadata["usage"]` (always, from `CampaignBudget.summary()`), and
  `metadata["status"] = "budget_exceeded"` only on a hit. `CampaignResult.token_usage` keeps its
  target-only meaning; no domain model changes.
- **FR-012 (CLI)**: `ziran scan --max-campaign-tokens INT --max-cost FLOAT`; one `UsageLedger`
  per scan built with `load_price_table()`; one `UsageTrackingClient` per stage around the judge
  client, the strategy client, each ensemble client and the prefilter client; budget row,
  unpriced-model warnings, summary rows, status row and resume hint as in US1/US5.
- **FR-013 (size guards)**: `scanner.py` stays <= 750 lines with a net-zero or negative diff;
  `attack_executor.py` is not touched; every other `agent_scanner` module stays <= 400 lines.
- **FR-014 (docs)**: `docs/guides/long-running-campaigns.md` gains a `## Token budget and cost
  cap` section: flags, stages, price table and override, null cost for unknown models, heuristic,
  cooperative overshoot up to `--concurrency` in-flight attacks, resume with a higher cap, and the
  limitations in Edge Cases.
- **FR-015 (no regressions)**: every existing test passes unmodified; no new runtime dependency;
  `uv.lock` unchanged.

### Assumptions (recorded, most conservative reading)
- The issue's `--max-tokens` is named `--max-campaign-tokens`: `--max-tokens` would read as the
  per-call `LLMConfig.max_tokens`. `--max-cost` keeps the issue's name (USD).
- The issue's config-file `budget` block is out of scope (release planner); flags and
  `scanner_config` keys only.
- The issue's "attack generation" stage maps to `strategy`: in `ziran scan` the only LLM use
  outside the judge stage is the LLM-adaptive strategy. Stage names: `judge`, `ensemble`,
  `prefilter`, `strategy`, `target`.
- The token cap counts all stages including `target` (the issue asks for a hard token budget for
  the campaign, and the target is part of it). The cost cap counts priced calls only; this is
  warned about at start and documented.
- The model key is the configured model (`client.config.model`), not the provider-resolved
  `LLMResponse.model`, so it matches the price table the operator writes.
- A budget-exceeded scan exits `0`: the issue asks for a clean stop with partial results, not a
  failure.
- Costs are estimates (list prices x token counts); no cache discounts, batch pricing or
  provider-side billing reconciliation.

### Key Entities
- **ModelPrice** (`input_per_mtok`, `output_per_mtok`), **PriceTable** (`version`, `currency`,
  `models`): frozen Pydantic, `extra="forbid"` (operator file is a trust boundary).
- **UsageEntry** (`stage`, `model`, `calls`, `prompt_tokens`, `completion_tokens`,
  `total_tokens`, `estimated_calls`, `cost_usd`), **UsageBudget** (`max_tokens`,
  `max_cost_usd`), **UsageSummary** (`currency`, `entries`, `total_tokens`, `total_cost_usd`,
  `unpriced_tokens`, `max_campaign_tokens`, `max_cost_usd`): Pydantic.
- **UsageLedger**, **CampaignBudget**: small service classes holding the above.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US5 pass as unit tests with stub `BaseLLMClient`s and `MockAgentAdapter` (no
  network, no LLM, no keys); the issue's four required test areas (accumulation, price lookup,
  heuristic fallback, cap enforcement) each have named tests.
- **SC-002**: the cap test proves a partial result with `status == "budget_exceeded"`, a kept
  checkpoint, and a resume that finishes the remaining vectors without re-running executed ones.
- **SC-003**: `tests/unit/application/test_scanner_size.py` passes; `git diff --stat` shows
  `scanner.py` with deletions >= insertions; `attack_executor.py` absent from the diff.
- **SC-004**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-005 (packaging)**: a built wheel contains `ziran/infrastructure/llm/prices.yaml`.
- **SC-006 (unverified offline)**: real provider token counts and real cost accuracy against a
  provider invoice need live model calls; not claimed. The PR says so.

# Implementation Plan: per-campaign token budget and cost accounting with a hard cap

**Branch**: `047-token-budget-cost-cap` | **Date**: 2026-10-03 | **Spec**: [spec.md](spec.md)
**Issue**: #399 (release 0.41.0) | **Base**: `develop` @ 7d4132e
**Parallel siblings**: #395 / spec 046 also edits `ziran/interfaces/cli/main.py` (the `ci`
command only). This plan's `main.py` edits are confined to the `scan` command (options,
signature, body) and `_display_results`; no shared helper is changed.

## Summary
A `BaseLLMClient` decorator (`UsageTrackingClient`) records prompt/completion tokens and the
configured model of every successful call into a shared `UsageLedger`, tagged with a stage fixed at
construction. `ziran scan` wraps one instance per stage (judge, strategy, each ensemble client,
prefilter); no call site changes. Target-agent tokens, already summed per vector, are recorded as
stage `target` by `PhaseExecutor`. A `PriceTable` (shipped `prices.yaml` plus optional
`.ziran/prices.yaml`) turns tokens into cost; unknown models cost `null`. A `CampaignBudget`
(ledger + limits) is checked before each vector (inside the concurrency slot) and before each
phase; on a hit the scanner stops scheduling, builds the partial result with
`metadata["status"] = "budget_exceeded"`, and keeps the checkpoint (which now also stores the
ledger) so `--resume` continues. The breakdown lands in `metadata["usage"]`;
`CampaignResult.token_usage` is untouched.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (usage + price models), PyYAML `safe_load` (price table), Click (scan flags); reuses `BaseLLMClient`, `many_shot.estimate_tokens`, the checkpoint/resume path, `PhaseExecutor`, `ResultBuilder`. No new dependencies.
**Storage**: shipped `ziran/infrastructure/llm/prices.yaml` plus optional operator `.ziran/prices.yaml`; usage ledger snapshot inside the existing `<output>/.checkpoint.json`.
**Testing**: pytest, `@pytest.mark.unit` / `@pytest.mark.integration`; stub `BaseLLMClient`s with
fixed usage (pattern of `tests/unit/test_scanner.py::TestJudgeTierMetadata._Stub`), the stub
executor/library/graph pattern of `tests/unit/application/test_phase_executor_checkpoint.py`,
`MockAgentAdapter` and `shared_attack_library` from `tests/conftest.py`, Click `CliRunner` with
the patching pattern of `tests/unit/test_cli_main.py::TestScanEnsembleWiring`. No network, no
LLM, no keys.
**Target Platform**: `ziran scan`; `AgentScanner` via `scanner_config`.
**Project Type**: single Python package.
**Performance Goals**: one dict update per LLM call and per vector; `exceeded()` is O(entries)
(<= ~10 entries).
**Constraints**: `scanner.py` is exactly 750 lines today and
`tests/unit/application/test_scanner_size.py` fails above 750 (and above 400 for any other
`agent_scanner` module): the `scanner.py` diff must be net-zero or negative.
`attack_executor.py` (395/400) is not touched. mypy strict; line length 100. No prompt/response
text in logs.
**Measured today** (`develop` @ 7d4132e, `wc -l`): `scanner.py` 750, `phase_executor.py` 337,
`checkpoint.py` 295, `result_builder.py` 149, `attack_executor.py` 395.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | Models, ledger, pricing math and budget logic are in `ziran/application/usage.py` (imports domain, pydantic and the logger, as every application module does). The decorator and the YAML file loader are infrastructure (`ziran/infrastructure/llm/usage_tracking_client.py`), importing the application ledger as `rate_limited_client.py` already imports `ziran.application.rate_limiting`. Clients are wrapped at the driving edge (`ziran/interfaces/cli/main.py`); the scanner receives the ledger through `scanner_config` and never imports infrastructure LLM code. No domain change. |
| II. Type safety | PASS | All data is Pydantic (`frozen`, `extra="forbid"` for the operator price file and the budget limits); `Stage` is a `Literal`; every function annotated. |
| III. Tests | PASS | Test-first per task: unit tests for models, ledger, pricing, heuristic, decorator, loader, phase-executor check, checkpoint persistence, result metadata, scanner end-to-end cap + resume with `MockAgentAdapter`, CLI wiring and summary rows. Existing tests unmodified. |
| IV. Async-first | PASS | The decorator is async; YAML loading is sync at the CLI entry point (as `load_detector_thresholds`). |
| V. Extensibility | PASS | No new port: the decorator implements the existing `BaseLLMClient`, stacked like `RateLimitedClient`. |
| VI. Simplicity | PASS | Reuses `estimate_tokens`, the checkpoint and resume path, `metadata` (as `judge_tiers`), `TokenUsage` on results. No config-file block, no tokenizer, no per-call log, no event bus. Two small service classes, one models module, one decorator module, one YAML file. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #399 implementer. Names, signatures, stage names, config keys, flags, metadata
keys and display strings MUST NOT change without updating this file.

### 1. `ziran/application/usage.py` (new)

```python
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ziran.domain.entities.phase import ScanPhase

Stage = Literal["judge", "ensemble", "prefilter", "strategy", "target"]
STAGES: tuple[Stage, ...] = ("judge", "ensemble", "prefilter", "strategy", "target")
TARGET_MODEL = "unknown"          # model key for the target stage; the target is never priced


class ModelPrice(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    input_per_mtok: float = Field(ge=0)      # USD per 1,000,000 prompt tokens
    output_per_mtok: float = Field(ge=0)     # USD per 1,000,000 completion tokens


class PriceTable(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    version: Literal[1] = 1
    currency: Literal["USD"] = "USD"
    models: dict[str, ModelPrice] = Field(default_factory=dict)

    def price_for(self, model: str) -> ModelPrice | None:
        """Exact model name first, then the part after the last '/'; None when absent."""

    def cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float | None:
        """round(prompt * in / 1e6 + completion * out / 1e6, 6); None when unpriced."""


class UsageEntry(BaseModel):
    stage: Stage
    model: str
    calls: int = Field(default=0, ge=0)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)          # always prompt + completion
    estimated_calls: int = Field(default=0, ge=0)       # calls where the char heuristic filled a 0
    cost_usd: float | None = None                       # filled only in UsageSummary; None = unknown


class UsageBudget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_tokens: int | None = Field(default=None, gt=0)
    max_cost_usd: float | None = Field(default=None, gt=0)


class UsageSummary(BaseModel):
    currency: Literal["USD"] = "USD"
    entries: list[UsageEntry]            # sorted by (STAGES.index(stage), model), cost_usd filled
    total_tokens: int
    total_cost_usd: float | None         # round(sum of known entry costs, 6); None if none known
    unpriced_tokens: int                 # total_tokens of entries whose cost_usd is None
    max_campaign_tokens: int | None
    max_cost_usd: float | None


class UsageLedger:
    """Per-campaign accumulator keyed by (stage, model). Event-loop-thread only; no lock."""

    def __init__(self, prices: PriceTable | None = None) -> None: ...   # None -> PriceTable()
    prices: PriceTable                                                   # public attribute

    def record(
        self,
        stage: Stage,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        *,
        estimated: bool = False,
    ) -> None: ...
    def total_tokens(self) -> int: ...
    def total_cost(self) -> float | None: ...       # sum of priced non-target entries; None if none
    def entries(self) -> list[UsageEntry]: ...      # copies, cost_usd None (checkpoint snapshot)
    def restore(self, entries: Iterable[UsageEntry]) -> None: ...  # adds counts (resume)
    def summary(self) -> list[UsageEntry]: ...      # sorted copies with cost_usd filled
                                                    # (target always None)


class CampaignBudget:
    """Ledger + limits for one campaign; checked cooperatively between vectors and phases."""

    def __init__(self, ledger: UsageLedger, limits: UsageBudget) -> None: ...
    ledger: UsageLedger
    limits: UsageBudget
    interrupted_phase: ScanPhase | None      # set by PhaseExecutor when it skips a vector

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> CampaignBudget:
        """config['usage_ledger'] (or a fresh UsageLedger()), UsageBudget(max_tokens=
        config.get('max_campaign_tokens'), max_cost_usd=config.get('max_cost')).
        Raises pydantic.ValidationError on invalid limits."""

    def exceeded(self) -> bool:
        """total_tokens >= max_tokens or (total_cost or 0.0) >= max_cost_usd (unset limits never
        hit). The first True logs warning 'campaign_budget_exceeded' with limit=('tokens'|'cost'),
        total_tokens, total_cost_usd, max_tokens, max_cost_usd; later calls do not log again."""

    def summary(self) -> UsageSummary: ...
```

### 2. `ziran/infrastructure/llm/usage_tracking_client.py` (new)

```python
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from ziran.application.attacks.many_shot import estimate_tokens
from ziran.application.usage import PriceTable
from ziran.infrastructure.llm.base import BaseLLMClient, LLMResponse

if TYPE_CHECKING:
    from ziran.application.usage import Stage, UsageLedger

DEFAULT_PRICE_TABLE = Path(__file__).with_name("prices.yaml")
OVERRIDE_PRICE_TABLE = Path(".ziran/prices.yaml")      # cwd-relative, like .ziran/detectors.yaml


class PriceTableError(ValueError):
    """A price table file is present but invalid. Message: 'invalid price table <path>: <err>'."""


class UsageTrackingClient(BaseLLMClient):
    """Records each successful call's tokens into *ledger* under a fixed *stage* (spec 047)."""

    def __init__(self, inner: BaseLLMClient, ledger: UsageLedger, *, stage: Stage) -> None:
        super().__init__(inner.config)
        ...

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        # response = await inner.complete(messages, temperature=..., max_tokens=..., **kwargs)
        # prompt = response.prompt_tokens or estimate_tokens("".join(m.get("content", "")
        #          for m in messages))
        # completion = response.completion_tokens or estimate_tokens(response.content)
        # ledger.record(stage, self.config.model, prompt, completion,
        #               estimated=not (response.prompt_tokens and response.completion_tokens))
        # return response                       # the same object, unchanged

    async def health_check(self) -> bool:      # delegates; records nothing
        ...
    # stream_complete is NOT overridden (base fallback routes through complete()).


def track(
    client: BaseLLMClient | None, ledger: UsageLedger, stage: Stage
) -> BaseLLMClient | None:
    """UsageTrackingClient(client, ledger, stage=stage), or None when client is None."""


def load_price_table(override: Path = OVERRIDE_PRICE_TABLE) -> PriceTable:
    """Shipped table, with override.models merged over it per model when override is a file.
    yaml.safe_load; empty file -> {}. Any read/parse/validation error -> PriceTableError."""
```

`ziran/infrastructure/llm/__init__.py` is not changed (import from the module path).

### 3. `ziran/infrastructure/llm/prices.yaml` (new, shipped)

```yaml
# Model list prices in USD per 1,000,000 tokens (spec 047). Costs are estimates.
# Every entry MUST cite the provider's public pricing page and the retrieval date, e.g.
#   gpt-x:  # source: <provider pricing URL> (retrieved YYYY-MM-DD)
# Never add a price that was not copied from such a page. Operators override or extend this
# table with .ziran/prices.yaml (same format; entries merged per model).
version: 1
currency: USD
models: {}
```
The implementer adds entries only if a pricing page can be retrieved in their environment, each
with a `# source:` comment; otherwise it ships exactly as above. Packaging: hatch
`[tool.hatch.build.targets.wheel] packages = ["ziran"]` already ships non-Python files under
`ziran/` (e.g. `ziran/application/attacks/many_shot_corpus.yaml`, attack-vector YAML); no
`pyproject.toml` change. Verified by building the wheel (task T014).

### 4. `ziran/application/agent_scanner/phase_executor.py` (edit, stays <= 400 lines)

- `PhaseExecutor.__init__(..., phase_timeout: float = 300.0, budget: CampaignBudget | None =
  None)`; stored as `self._budget`. `CampaignBudget` imported under `TYPE_CHECKING`.
- In `_run_attack`, first statement inside `async with semaphore:`:
  ```python
  if self._budget is not None and self._budget.exceeded():
      self._budget.interrupted_phase = phase
      return
  ```
  (the skipped vector is not executed, not added to `tested_vector_ids` / `attack_results`, and
  emits no `ATTACK_COMPLETE`).
- Under the existing result lock, after `phase_tokens = phase_tokens + result.token_usage`:
  ```python
  if self._budget is not None:
      tu = result.token_usage
      self._budget.ledger.record("target", TARGET_MODEL, tu.prompt_tokens, tu.completion_tokens)
  ```
- `execute(...)` signature unchanged. `budget=None` (all existing callers and the scanner's
  `_execute_phase` back-compat wrapper) = today's behaviour exactly.

### 5. `ziran/application/agent_scanner/checkpoint.py` (edit, stays <= 400 lines)

- `CampaignCheckpoint.usage: list[UsageEntry] = Field(default_factory=list, description="Usage
  ledger snapshot (spec 047)")`. Checkpoints without the key load with `[]`.
- `CheckpointManager.build_checkpoint(..., remaining_phases, usage: list[UsageEntry] | None =
  None)` -> `usage=usage or []`.
- `IncrementalCheckpointer.__init__(..., flush_interval=..., budget: CampaignBudget | None =
  None)`. `_write`: with `stopped = budget.interrupted_phase` (None without a budget), writes
  `phase_results=[p for p in phase_results if p.phase != stopped]`, `remaining_phases` = the
  current values with `stopped.value` prepended when not already present, and
  `usage=budget.ledger.entries()` (`None` without a budget).
- `load_resume_state(manager, phases, ledger: UsageLedger | None = None)`: when `ledger` is given,
  `ledger.restore(ckpt.usage)`. `ResumeState` unchanged.

### 6. `ziran/application/agent_scanner/result_builder.py` (edit)

`ResultBuilder.build(..., judge_tiers=None, usage: CampaignBudget | None = None)`: when `usage` is
not None, `metadata["usage"] = usage.summary().model_dump(mode="json")` and, if
`usage.exceeded()`, `metadata["status"] = "budget_exceeded"`. Nothing else changes.

### 7. `ziran/application/agent_scanner/scanner.py` (edit, net <= 0 lines; today 750)

| Where | Change | Lines |
|---|---|---|
| imports | `from ziran.application.usage import CampaignBudget` | +1 |
| `__init__`, after `self._detector_pipeline = ...` | `self._budget = CampaignBudget.from_config(self.config)` | +1 |
| `__init__` docstring "Supported keys" | new line `- ``usage_ledger``, ``max_campaign_tokens``, ``max_cost``: usage budget (spec 047).` (99 chars with indent, within the 100 limit) | +1 |
| resume | `_rs = load_resume_state(checkpoint_manager, phases, self._budget.ledger)` | 0 |
| `PhaseExecutor(...)` in `run_campaign` | `budget=self._budget,` | +1 |
| `IncrementalCheckpointer(...)` | `budget=self._budget,` | +1 |
| loop | `while True:` -> `while not self._budget.exceeded():` | 0 |
| post utility | `if utility_tasks and _baseline_score is not None and not self._budget.exceeded():` | 0 |
| `result_builder.build(...)` | `usage=self._budget,` | +1 |
| cleanup | `if checkpoint_manager is not None and not self._budget.exceeded():` | 0 |
| pay-back | delete these six redundant comment lines: `# Default to FixedStrategy for backwards compatibility`, `# Build sub-components`, `# Check strategy termination`, `# Ask strategy for the next phase`, `# Remove executed phase from remaining`, `# Aggregate tokens` | -6 |

Net: +6 -6 = 0; `wc -l scanner.py` stays 750.

`_execute_phase` / `_execute_attack` back-compat wrappers are unchanged (no budget).

### 8. `ziran/interfaces/cli/main.py` (edit: `scan` and `_display_results` only)

New options, placed after `--checkpoint-flush-interval`:
```python
@click.option(
    "--max-campaign-tokens",
    type=click.IntRange(min=1),
    default=None,
    help="Stop scheduling new attacks once the campaign has used this many tokens across all "
    "stages (judge, ensemble, prefilter, strategy, target). Cooperative: attacks already "
    "running finish, so the total can overshoot by up to --concurrency attacks.",
)
@click.option(
    "--max-cost",
    type=click.FloatRange(min=0, min_open=True),
    default=None,
    help="Stop scheduling new attacks once the estimated LLM cost reaches this many USD. "
    "Only models with a price (shipped table or .ziran/prices.yaml) count. Cooperative.",
)
```
`scan(..., max_campaign_tokens: int | None, max_cost: float | None)` (appended after
`checkpoint_flush_interval` in the signature, in option order).

Body (all inside `scan`):
1. Config table, after `Concurrency`: when either is set, row `"Budget"` =
   `" · ".join(p for p in (f"{max_campaign_tokens:,} tokens" if max_campaign_tokens else "",
   f"${max_cost:g}" if max_cost else "") if p)`.
2. Before the LLM-client block: `prices = load_price_table()` (`PriceTableError` ->
   `raise click.ClickException(str(exc)) from None`, exit 1); `ledger = UsageLedger(prices)`;
   `scanner_config` gains `"usage_ledger": ledger`, `"max_campaign_tokens": max_campaign_tokens`,
   `"max_cost": max_cost`.
3. `scanner_config["llm_client"] = track(llm_client, ledger, "judge")` (the raw `llm_client`
   variable is kept for the `if llm_client is not None` detector block and the strategy).
4. After `_scan_detector_config(...)` returns a config:
   `detector_config = dataclasses.replace(detector_config, judge_clients={n:
   UsageTrackingClient(c, ledger, stage="ensemble") for n, c in
   detector_config.judge_clients.items()}, prefilter_client=track(detector_config.prefilter_client,
   ledger, "prefilter"))` before it is stored in `scanner_config` (`UsageTrackingClient` directly in
   the dict so the values stay `BaseLLMClient`, not `| None`). `_scan_detector_config` itself is
   unchanged.
5. `build_strategy(strategy, stop_on_critical, track(llm_client, ledger, "strategy"))`.
6. When `max_cost` is set: for each distinct `config.model` of the tracked clients (judge,
   ensemble, prefilter) with `prices.price_for(model) is None`, print
   `"[yellow]Warning:[/yellow] no price for model '<m>': its calls do not count towards
   --max-cost"`; when no LLM client exists, print `"[yellow]Warning:[/yellow] --max-cost cannot
   trigger: no LLM client is configured and the target stage is not priced"`.
7. After `_display_results(result)`: when `result.metadata.get("status") == "budget_exceeded"`,
   print `f"[yellow]Budget reached; checkpoint kept in {output_dir}. Re-run with --resume and a
   higher cap to continue.[/yellow]"`. Exit code unchanged (0).

`_display_results`, after the `Judge Routing` row:
```python
usage = result.metadata.get("usage")
if usage:
    for e in usage["entries"]:
        cost = "cost n/a" if e["cost_usd"] is None else f"${e['cost_usd']:.4f}"
        summary_table.add_row(
            f"Usage · {e['stage']} · {e['model']}", f"{e['total_tokens']:,} tokens · {cost}"
        )
    summary_table.add_row("All-Stage Tokens", f"{usage['total_tokens']:,}")
    total = usage["total_cost_usd"]
    cost_text = "n/a" if total is None else f"${total:.4f}"
    if usage["unpriced_tokens"]:
        cost_text += f" ({usage['unpriced_tokens']:,} tokens unpriced)"
    summary_table.add_row("Estimated Cost", cost_text)
if result.metadata.get("status") == "budget_exceeded":
    summary_table.add_row("Status", "[bold yellow]BUDGET EXCEEDED (partial results)[/bold yellow]")
```
Imports: `dataclasses` (stdlib, top-level or local), `UsageLedger` from `ziran.application.usage`,
`PriceTableError`, `UsageTrackingClient`, `load_price_table`, `track` from
`ziran.infrastructure.llm.usage_tracking_client` (local imports inside `scan`, matching the
existing lazy-import style).

### 9. Output shapes

`CampaignResult.metadata["usage"]` (JSON, from `UsageSummary.model_dump(mode="json")`):
```json
{
  "currency": "USD",
  "entries": [
    {"stage": "judge", "model": "gpt-4o", "calls": 12, "prompt_tokens": 9600,
     "completion_tokens": 1200, "total_tokens": 10800, "estimated_calls": 0, "cost_usd": 0.036},
    {"stage": "target", "model": "unknown", "calls": 12, "prompt_tokens": 0,
     "completion_tokens": 0, "total_tokens": 0, "estimated_calls": 0, "cost_usd": null}
  ],
  "total_tokens": 10800,
  "total_cost_usd": 0.036,
  "unpriced_tokens": 0,
  "max_campaign_tokens": 50000,
  "max_cost_usd": null
}
```
(illustrative shape only; numbers are not measurements). `metadata["status"] ==
"budget_exceeded"` only when a cap was hit; absent otherwise. `CampaignResult.token_usage`
(target-only) unchanged. `.checkpoint.json` gains `"usage": [UsageEntry...]` (cost_usd null).

| Key | Accepted by | Type | Meaning |
|---|---|---|---|
| `--max-campaign-tokens` / `scanner_config["max_campaign_tokens"]` | `ziran scan` / `AgentScanner` | int > 0 | all-stage token cap |
| `--max-cost` / `scanner_config["max_cost"]` | `ziran scan` / `AgentScanner` | float > 0 (USD) | priced-cost cap |
| `scanner_config["usage_ledger"]` | `AgentScanner` | `UsageLedger` | shared with tracked clients; fresh unpriced ledger when absent |
| `.ziran/prices.yaml` | `load_price_table` | YAML (`PriceTable`) | operator price override |

## Acceptance criteria -> offline proof

| Criterion (issue, narrowed by the brief) | Proven by | Live model? |
|---|---|---|
| Completed campaign prints and serialises per-stage, per-model tokens and cost | `tests/unit/test_scanner.py::TestUsageAccounting` (US1.1-US1.2: `MockAgentAdapter` + tracked stub judge + test price table -> `metadata["usage"]` entries and costs; `token_usage` unchanged); `tests/unit/test_cli_main.py::TestDisplayUsage` (US1.4 rows present / absent); US1.3: existing JSON dump serialises `metadata` (asserted on `_dump_campaign_result` output in the same CLI test) | No |
| Low cap stops at the cap with partial results marked `budget_exceeded` | `tests/unit/test_scanner.py::TestBudgetCap` (US2.1-US2.3, US2.5-US2.8 incl. checkpoint kept and resume); `tests/unit/application/test_phase_executor_budget.py` (skip before vector, `interrupted_phase`, overshoot <= concurrency, target recording) | No |
| Cost = tokens x price within rounding | `tests/unit/test_usage.py::TestPricing` (US3.1, US3.4, rounding to 6 decimals) | No |
| Unknown-usage calls use the char heuristic | `tests/unit/test_usage_tracking_client.py::TestHeuristic` (US3.2) | No |
| Unknown model -> cost null, never 0 | `tests/unit/test_usage.py::TestPricing` (US3.3) and `TestUsageAccounting` target entry | No |
| Unit tests: accumulation, price lookup, heuristic, cap enforcement | `test_usage.py::TestLedger`, `TestPricing`, `TestBudget`; `test_usage_tracking_client.py`; `test_phase_executor_budget.py`; `TestBudgetCap` | No |
| Ledger persisted in the checkpoint; `--resume` works after a hit | `tests/unit/application/test_checkpoint.py::TestUsagePersistence` (round-trip, old file without `usage`, interrupted phase excluded/re-queued); US2.5 in `TestBudgetCap` | No |
| Flags / scanner_config keys / per-stage wrapping | `tests/unit/test_cli_main.py::TestScanBudgetWiring` (US5.1-US5.4, US4.3) and `TestBudgetCap` API case (US5.5) | No |
| Price table shipped and valid, override merged | `test_usage_tracking_client.py::TestPriceTable` (US4.1-US4.3); wheel listing in T014 | No |
| Size guards | `tests/unit/application/test_scanner_size.py` (unmodified) + `git diff --numstat` on `scanner.py` | No |
| Real provider usage numbers and invoice-level cost accuracy | not provable offline | **Yes: unverified**, reported as such in the PR (SC-006) |

## Project Structure

### Documentation (this feature)
```text
specs/047-token-budget-cost-cap/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/application/usage.py                              # new: models, UsageLedger, CampaignBudget
ziran/infrastructure/llm/usage_tracking_client.py       # new: decorator, track, load_price_table
ziran/infrastructure/llm/prices.yaml                    # new: shipped price table (cited or empty)
ziran/application/agent_scanner/phase_executor.py       # edit: budget kwarg, check, target record
ziran/application/agent_scanner/checkpoint.py           # edit: usage field, interrupted phase, restore
ziran/application/agent_scanner/result_builder.py       # edit: usage kwarg -> metadata
ziran/application/agent_scanner/scanner.py              # edit: net <= 0 lines
ziran/interfaces/cli/main.py                            # edit: scan options/body, _display_results
docs/guides/long-running-campaigns.md                   # edit: "Token budget and cost cap" section
tests/unit/test_usage.py                                # new
tests/unit/test_usage_tracking_client.py                # new
tests/unit/application/test_phase_executor_budget.py    # new
tests/unit/application/test_checkpoint.py               # extend
tests/unit/application/test_result_builder.py           # extend
tests/unit/test_scanner.py                              # extend
tests/unit/test_cli_main.py                             # extend
```
**Structure Decision**: one application module for everything that is pure logic, one
infrastructure module for the client decorator and file loading; the agent_scanner edits are
small hooks into existing seams so `scanner.py` gains no lines.

## Follow-ups (noted, not filed, out of scope)
- `LLMAdaptiveStrategy` calls `asyncio.run(...)` from inside the running event loop
  (`ziran/application/strategies/llm_adaptive.py`, two call sites), which raises before the client
  is awaited; the strategy stage therefore records 0 calls until that is fixed.
- Config-file `budget` block; embedding (semantic tier) cost; pentest and web UI budgets; a
  target-stage heuristic (needs per-invocation text inside `attack_executor.py`, at its size cap).

## Release note for the implementer
Commit as `feat(scan): per-campaign token budget and cost accounting` (tests may be split as
`test(scan): ...`, docs as `docs: ...`). No `!`, no `BREAKING CHANGE` (new optional flags,
additive metadata keys and checkpoint field), no `Co-Authored-By`. PR targets `develop`, links
#399, states that the price table ships empty unless entries were copied from a cited pricing
page, and reports SC-006 as unverified.

## Phases
- P1 (tests first): `usage.py` models, ledger, pricing, budget (FR-003, FR-004, FR-006).
- P2 (tests first): decorator, heuristic, price-table loader, shipped YAML (FR-001, FR-002,
  FR-005).
- P3 (tests first): phase-executor check + target recording; checkpoint persistence; result
  metadata (FR-008..FR-011).
- P4 (tests first): scanner wiring within the line budget; end-to-end cap + resume (FR-007,
  FR-008, FR-013).
- P5 (tests first): CLI flags, wrapping, warnings, summary rows (FR-012).
- P6: docs (FR-014); wheel check; gates.
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.

## Complexity Tracking
None.

## Implementation notes (#399)
- Additive, not a deviation: `UsageTrackingClient.stage` is a public attribute (the CLI tests assert the stage of each wrapped client through it).
- `prices.yaml` ships exactly as in section 3 (`models: {}`): no provider pricing page was retrieved in the implementation environment.
- Wheel check (T014): `uv build --wheel` lists `ziran/infrastructure/llm/prices.yaml` in the wheel.

# Implementation Plan: PAIR attacker-LLM refinement as a vector tactic

**Branch**: `docs/081-pair-generator` (spike); the build takes `feat/0NN-pair-tactic` |
**Date**: 2026-11-18 | **Spec**: [spec.md](spec.md) | **Research**: [research.md](research.md)

## Summary

Add PAIR as `tactic: pair`. `AttackExecutor` already hands non-`single` tactics to
`TacticExecutor`; it hands `pair` to a new `PairExecutor` the same way. Each iteration makes one
attacker call, one `adapter.invoke` and one `DetectorPipeline.evaluate`, as the spike did and as
`TacticExecutor` does (tactics.py calls `adapter.invoke` and `pipeline.evaluate` directly). The
loop stops on `verdict.successful` and refines on the quality composite. Bounds are an iteration
cap, the campaign budget checked each iteration, and a deadline that ends before the phase's.
PAIR vectors queue after every static vector, so they never delay one. PAIR results are never
cached. This plan covers the first slice only, in two PRs; the CLI flag and
hybrid mode come later.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (`PairConfig`), stdlib `asyncio`/`hashlib`/`json`; reuses
`BaseLLMClient`, `DetectorPipeline`, `CampaignBudget`, `UsageLedger`, `estimate_tokens`. No new
dependencies.
**Storage**: N/A. The trajectory goes into `AttackResult.evidence`. The spec-049 scan cache never
stores a PAIR result (section 5).
**Testing**: pytest, `@pytest.mark.unit`, scripted attacker and toy target copied from the spike.
**Project Type**: library and CLI (CLI unchanged in this slice).
**Constraints**: offline tests; no key; a scan without `tactic: pair` vectors is unchanged.
**Scale/Scope**: about 580 changed lines in two PRs, about 380 and 200 (spec.md, smallest first
build slice).

## Constitution Check

| Principle | Check |
|---|---|
| I. Hexagonal | `PairConfig` in `domain/entities`; `PairExecutor` in `application/attacks`. The attacker is a `BaseLLMClient` passed in and imported under `TYPE_CHECKING` only, as `pipeline.py` and `llm_judge.py` do. Attacker tokens go into the injected `CampaignBudget.ledger` (application), so no application code calls infrastructure `track()`; only `interfaces/cli` wraps clients, as today. A pending reply is detected by its `reason` attribute, so there is no runtime import of `PendingResponse`. PASS |
| II. Type safety | Pydantic `PairConfig`; mypy strict. PASS |
| III. Tests | unit tests for every scenario; `MockAgentAdapter` cannot model a guard, so the toy target lives in the test file. PASS, noted |
| IV. Async | every call awaited; the deadline is `asyncio.timeout_at`. PASS |
| V. Vectors as YAML | a PAIR vector is YAML with `tactic: pair` and a `pair:` block. PASS |
| VI. Simplicity | no new port (one implementation), no flag, one stream, no seed field, no cache key change. PASS |

## Design

### 1. `PairConfig` (`ziran/domain/entities/attack.py`)

```python
class PairConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a stray `seed:` is an error, not a no-op
    max_iterations: int = Field(default=20, ge=1, le=100)
    timeout_seconds: float = Field(default=240.0, gt=0)
```

`AttackVector.pair: PairConfig | None = None`, documented beside `many_shot`. The `tactic` field
description gains `pair` in PR 2 (section 4). There is no `seed`: the loop draws no
randomness, and reproducibility belongs to the attacker client (a scripted or replayed client is
deterministic; the live client passes no seed).

### 2. `PairExecutor` (`ziran/application/attacks/pair.py`)

`PairExecutor(adapter, attacker, budget).execute(attack, pipeline, deadline) -> AttackResult`:

1. Seed prompt: the vector's first rendered prompt; goal: `attack.description`.
2. Loop `i` from 1 to `max_iterations` inside `asyncio.timeout_at(deadline)`:
   - stop with `budget` if `budget.exceeded()`;
   - attacker request: one user message holding goal, iteration, last and best attempts with
     scores (spike `run_pair`); attacker system prompt is a module constant;
   - a reply with a `reason` attribute (spec-064 `PendingResponse`) stops with `pending`;
   - record the attacker call in `budget.ledger` under `attacker`, filling a 0 with
     `estimate_tokens`, as `UsageTrackingClient` does; an unparseable reply counts an
     `attacker_parse_errors` and keeps the last prompt;
   - `adapter.invoke(prompt)`, then the `AttackExecutor` invariants: `drop_reserved` on
     `response.metadata`, add the response tokens to `token_usage`, and skip `_is_error_response`
     replies. A raised error, a timeout or a sentinel reply scores 0 and adds 1 to
     `prompt_errors`;
   - `pipeline.evaluate(prompt, response, attack.prompts[0], attack)`;
   - score: 1.0 on success, else the quality composite, else 0.0;
   - success returns at once.
3. On `TimeoutError` from the deadline, stop with `timeout`; at the end, return the best attempt.
4. Evidence: `{"pair": {"iterations", "stop", "attacker_model", "trajectory": [{"i", "score",
   "prompt_sha256"}], "attacker_parse_errors"}}`, plus `prompt_errors` when non-zero, plus on
   success the same detector keys `AttackExecutor` writes (`response_snippet`, `tool_calls`,
   `matched_indicators`, `detector_scores`, `detector_reasoning`, `side_effects`, review
   evidence). `token_usage` is the sum over every target call.

Target tokens are not written to the ledger here. `PhaseExecutor` records `result.token_usage`
under `target` when the vector ends (phase_executor.py, the `ledger.record("target", ...)` call),
so recording them per iteration would count them twice. The per-iteration budget check therefore
sees attacker and judge tokens (the judge client is wrapped by the CLI) and the target tokens of
vectors already finished. Overshoot is up to one iteration per PAIR vector in flight, so up to
`max_concurrent_attacks` (default 5) iterations.

### 3. Scheduling and deadline: PAIR never delays a static vector

Today `PhaseExecutor` wraps the whole phase gather in `asyncio.timeout(phase_timeout)` (300 s by
default) and each vector in `asyncio.timeout(attack_timeout)` (60 s), under one
`asyncio.Semaphore(max_concurrent)` (5 slots). Two failures follow for PAIR:

- Either outer timer cancels a running PAIR vector, losing its best attempt, and the phase timer
  also cancels every other vector still running. A nested timeout inside the vector does not help
  when the outer one is earlier.
- A PAIR vector holds a slot for up to its whole timeout, not 60 s. Static vectors queued behind
  it start late, and the phase timer drops them unrecorded. The arch gate's scaled model of the
  first design recorded 60 of 60 static vectors alone, but 10 of 60 with five PAIR vectors queued
  first.

The design has three parts:

1. **PAIR vectors queue last.** Before building the task list, `PhaseExecutor` moves every
   `tactic: pair` vector after every other vector (a stable sort on `tactic == "pair"`).
   `asyncio.Semaphore` wakes waiters in FIFO order and the tasks reach `acquire` in list order, so
   every static vector acquires its slot before any PAIR vector does. The static vectors' schedule
   is then the same as in the same phase with no PAIR vector: a PAIR vector only takes a slot that
   no static vector is waiting for.
2. **The phase gets time for its PAIR vectors.** With k PAIR vectors in the phase, the phase timer
   becomes `phase_timeout + ceil(k / max_concurrent) * max(pair.timeout_seconds)`, logged as
   `phase_timeout_extended` with k and the new value. At the defaults, 1 to 5 PAIR vectors add
   240 s (300 s becomes 540 s). A phase with no PAIR vector keeps `phase_timeout` unchanged.
3. **Each PAIR vector stops before the phase does.** The deadline is taken inside
   `async with semaphore`, next to the budget check, so queue time does not eat PAIR time:
   `deadline = min(loop.time() + pair.timeout_seconds, phase_deadline - PAIR_GRACE_SECONDS)`.
   `PAIR_GRACE_SECONDS = 5.0` is a module constant of `phase_executor.py`, which tests patch. The
   vector runs `attack_executor.execute(attack, deadline=deadline)` under
   `asyncio.timeout_at(deadline + PAIR_GRACE_SECONDS)` in place of `attack_timeout`, as a backstop
   only. `PairExecutor` stops at `deadline` and returns its best attempt with
   `pair.stop == "timeout"`. A PAIR vector that gets its slot with less than `PAIR_GRACE_SECONDS`
   left is recorded as an error result naming the phase deadline, with no target call.

The guarantee, and its limits:

- Static vectors acquire their slots in the same order and at the same times as in the same phase
  with no PAIR vector, so each is recorded whenever it would be without PAIR; the extension only
  adds time. If static work alone overruns `phase_timeout`, the phase drops static vectors today
  and still does; PAIR changes nothing there.
- Every PAIR vector in the phase is recorded: with a best attempt (`success`, `max_iterations`,
  `budget` or `timeout`) or, when the phase time is spent, with the skip error. The one exception
  is the campaign budget's existing between-vector skip, which leaves any vector unrecorded so a
  resume runs it.
- The phase timer can still cut a PAIR vector whose adapter ignores cancellation for longer than
  the grace. The result is then lost, as for any vector today.
- The extension makes a phase with PAIR vectors run longer. That cost is the opt-in's, and the
  cost warning names it.

Sizing: about 30 lines in `phase_executor.py`, 5 in `attack_executor.py` (the `deadline` keyword
passed through), 10 in `pair.py`, and 4 tests.

### 4. Wiring

- `TacticType.PAIR = "pair"` (`tactics.py`) and `pair` in the `AttackVector.tactic`
  description land in PR 2 with the dispatch. Before PR 2, `tactic: pair` would route to
  `TacticExecutor` as a plain multi-turn sequence, so nothing documents it until then.
- `AttackExecutor.__init__(..., attacker: BaseLLMClient | None = None, budget: CampaignBudget |
  None = None)`; `execute(attack, *, deadline: float | None = None)`. In `execute`,
  `if attack.tactic == "pair":` comes before the `TacticExecutor` branch. No attacker: an error
  result, no target call. No budget: a fresh `CampaignBudget(UsageLedger(), UsageBudget())`.
- `AgentScanner` passes `self.config.get("attacker_llm_client")` unchanged and `self._budget`
  (built by `CampaignBudget.from_config`, so it holds the CLI's `usage_ledger` when given).
- `usage.py`: `"attacker"` in `Stage` and `STAGES`.
- A later CLI slice builds the attacker with `create_llm_client` in `interfaces/cli/main.py` and
  passes it unwrapped, since the executor records its tokens.
- The `attacker_llm_client` entry in the `AgentScanner` config docstring warns: pass the client
  unwrapped; wrapping it with `track()` counts its tokens twice (the wrapper's stage plus
  `attacker`).

### 5. Scan cache (spec 049)

`build_cache_context` keys on the judge, prefilter and detector models, not on an attacker, and
`is_cacheable` stores a failed result that has a response. A cached PAIR failure would come back
after the operator switches to a stronger attacker, hiding a finding. The slice excludes PAIR
results from the cache: `is_cacheable` returns False when `result.evidence` holds `pair`. A lookup
for a PAIR vector then always misses. Putting the attacker model and `PairConfig` into the context
instead is left for when cost makes caching worth it.

### 6. Cost warning

The spec's cost warning goes into the `PairExecutor` docstring and `docs/concepts/attack-vectors.md`
beside `many_shot`.

## Rollback

Revert the build PRs. No data format changes: `pair` evidence is additive, the `attacker` stage
appears in a checkpoint only when a PAIR vector ran, and no cache entry is ever written for PAIR.

## Later slices (not planned here)

1. CLI: `--attacker-model` and a docs page; needs a live efficacy run first.
2. Hybrid attacker: a stream checkpoint so each record, send and replay round invokes the target
   once (research.md, hybrid). A hybrid judge inside the loop goes with it.
3. Parallel streams, one shipped `tactic: pair` vector, and PAIR-aware cache keys.

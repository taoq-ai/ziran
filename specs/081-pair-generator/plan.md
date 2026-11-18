# Implementation Plan: PAIR attacker-LLM refinement as a vector tactic

**Branch**: `docs/081-pair-generator` (spike); the build takes `feat/0NN-pair-tactic` |
**Date**: 2026-11-18 | **Spec**: [spec.md](spec.md) | **Research**: [research.md](research.md)

## Summary

Add PAIR as `tactic: pair`. `AttackExecutor` already hands non-`single` tactics to
`TacticExecutor`; it hands `pair` to a new `PairExecutor` the same way. Each iteration makes one
attacker call, one `adapter.invoke` and one `DetectorPipeline.evaluate`, exactly as the spike
did. The loop stops on `verdict.successful` and refines on the quality composite. Bounds are an
iteration cap, the campaign budget checked each iteration, and a PAIR timeout. This plan covers
the first slice only; the CLI flag and hybrid mode come later.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (`PairConfig`), stdlib `asyncio`/`hashlib`/`json`/`random`;
reuses `BaseLLMClient`, `DetectorPipeline`, `CampaignBudget`, `track`. No new dependencies.
**Storage**: N/A. The trajectory goes into `AttackResult.evidence`.
**Testing**: pytest, `@pytest.mark.unit`, scripted attacker and toy target copied from the spike.
**Project Type**: library and CLI (CLI unchanged in this slice).
**Constraints**: offline tests; no key; a scan without `tactic: pair` vectors is unchanged.
**Scale/Scope**: about 370 changed lines (spec.md, smallest first build slice).

## Constitution Check

| Principle | Check |
|---|---|
| I. Hexagonal | `PairConfig` in `domain/entities`; `PairExecutor` in `application/attacks`; the attacker is a `BaseLLMClient` passed in, imported under `TYPE_CHECKING` as the pipeline does. PASS |
| II. Type safety | Pydantic `PairConfig`; mypy strict. PASS |
| III. Tests | unit tests for every scenario; `MockAgentAdapter` cannot model a guard, so the toy target lives in the test file. PASS, noted |
| IV. Async | every call awaited; the timeout is `asyncio.timeout`. PASS |
| V. Vectors as YAML | a PAIR vector is YAML with `tactic: pair` and a `pair:` block. PASS |
| VI. Simplicity | no new port (one implementation), no flag, one stream. PASS |

## Design

### 1. `PairConfig` (`ziran/domain/entities/attack.py`)

```python
class PairConfig(BaseModel):
    max_iterations: int = Field(default=20, ge=1, le=100)
    seed: int = 0
    timeout_seconds: float = Field(default=600.0, gt=0)
```

`AttackVector.pair: PairConfig | None = None`, documented beside `many_shot`.

### 2. `PairExecutor` (`ziran/application/attacks/pair.py`)

`PairExecutor(adapter, attacker).execute(attack, pipeline, budget) -> AttackResult`:

1. Seed prompt: the vector's first rendered prompt; goal: `attack.description`.
2. Loop `i` from 1 to `max_iterations` inside `asyncio.timeout(timeout_seconds)`:
   - stop with `budget` if `budget.exceeded()`;
   - attacker request: one user message holding goal, iteration, last and best attempts with
     scores (spike `run_pair`); attacker system prompt is a module constant;
   - `PendingResponse` stops with `pending`; an unparseable reply counts an
     `attacker_parse_errors` and keeps the last prompt;
   - `adapter.invoke`, then `pipeline.evaluate(prompt, response, attack.prompts[0], attack)`;
   - score: 1.0 on success, else the quality composite, else 0.0;
   - success returns at once.
3. On `TimeoutError` stop with `timeout`; at the end, return the best attempt.
4. Evidence: `{"pair": {"iterations", "stop", "seed", "trajectory": [{"i", "score",
   "prompt_sha256"}], "attacker_parse_errors"}}` plus the detector evidence on success, the same
   keys `AttackExecutor` writes.

The PAIR timeout must sit inside the per-attack timeout. `PhaseExecutor` wraps each vector in
`asyncio.timeout(attack_timeout)` (60 s by default), so the scanner gives a `tactic: pair` vector
`max(attack_timeout, pair.timeout_seconds)`. One line in `phase_executor.py`.

### 3. Wiring

- `TacticType.PAIR = "pair"` (`tactics.py`).
- `AttackExecutor.__init__(..., attacker: BaseLLMClient | None = None, budget: CampaignBudget |
  None = None)`; in `execute`, `if attack.tactic == "pair":` before the `TacticExecutor` branch.
  No attacker: an error result, no target call.
- `AgentScanner` passes `track(self.config.get("attacker_llm_client"), ledger, "attacker")` and
  its `CampaignBudget`.
- `usage.py`: `"attacker"` in `Stage` and `STAGES`.

### 4. Cost warning

The spec's cost warning goes into the `PairExecutor` docstring and `docs/concepts/attack-vectors.md`
beside `many_shot`.

## Rollback

Revert the build PR. No data format changes: `pair` evidence is additive, and the `attacker` stage
appears in a checkpoint only when a PAIR vector ran.

## Later slices (not planned here)

1. CLI: `--attacker-model` and a docs page; needs a live efficacy run first.
2. Hybrid attacker: a stream checkpoint so each record, send and replay round invokes the target
   once (research.md, hybrid).
3. Parallel streams, and one shipped `tactic: pair` vector.

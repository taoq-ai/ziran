# Feature Specification: PAIR attacker-LLM refinement as a vector tactic

**Feature Branch**: `docs/081-pair-generator`
**Created**: 2026-11-18
**Status**: Draft (spike done; build not started)
**Plan item**: ISSUE-275-PAIR-SPIKE (goal G-5).
**Issue**: #275 (gradient-based adversarial suffix generation, GCG / PAIR).
**Base**: `develop` @ c5d75eb.
**Evidence**: [research.md](research.md), produced by [spike/pair_spike.py](spike/pair_spike.py).

## The promise in our own words

Before anyone builds #275, find out whether PAIR (Chao et al. 2024, arXiv 2310.08419) fits ziran.
PAIR uses an attacker LLM that rewrites a prompt after each target reply, guided by a judge's
score, until the target complies or a bound is reached. The spike wires a bounded PAIR loop through
seams ziran already has: a `BaseLLMClient` as the attacker, the `DetectorPipeline` and its LLM
judge as the scorer, the adapter call `AttackExecutor` makes, and the spec-047 ledger and budget.
It runs offline against a toy target with a scripted attacker. It measures iterations to success,
tokens per vector, determinism under a fixed seed, and which judge signal can drive the loop. The
answer is this spec, with research, plan and tasks, and it stops before implement.

Acceptance, as we read it:

1. `research.md` holds, from the prototype run, the iterations to success, the tokens per vector,
   the fixed-seed check and the chosen judge signal, each with the command that produced it.
2. The spike PR changes no file under `ziran/`, `tests/` or `benchmarks/`.
3. Nothing in this folder uses prompts or goals from a public jailbreak or agent-injection
   benchmark set, or from the ziran-paper held-out sets (specs 062, 065, 070).
4. This spec states go or no-go with the evidence, the cost warning #275 asks for, and the
   smallest first build slice with its files and size.

Out of scope here: GCG, universal triggers, any merged runtime code, and the CLI flag.

## Finding: go, for one bounded slice

**Go** for a first slice of about 370 changed lines: PAIR as a `tactic: pair` vector run by a new
executor, reached from the Python API, with offline tests. **No-go** for the full #275 design
sketch (new domain port, `--advanced-attacks` flag, `advanced_generator` YAML field) until that
slice ships and a live run measures efficacy.

Evidence (all from [research.md](research.md), offline, 50 seeds):

- **It fits without changing a seam.** The attacker was a plain `BaseLLMClient`, the scorer the
  existing `DetectorPipeline`, the accounting the existing `UsageTrackingClient` and
  `CampaignBudget`. The spike changed no ziran file.
- **The loop works and the cap holds.** With the graded judge signal, 50 of 50 toy runs found the
  secret (median 13 iterations, max 37). A 1,500-token cap stopped a run after 3 iterations, 695
  tokens over the cap (one cooperative check per iteration).
- **It is deterministic offline.** The same seed gave the same trajectory, a different seed a
  different one, and a cassette replay equalled the direct run. Live runs are not reproducible:
  the live client passes no seed.
- **The judge signal is known.** The deterministic pipeline score is binary, so it can stop the
  loop but not steer it (40 of 50 runs, median 15). The quality judge's StrongREJECT composite
  steers it (50 of 50, 40 percent fewer tokens). It is readable from `evaluate()` on failures,
  but `AttackExecutor.execute()` drops it, so the loop calls the adapter and the pipeline itself.
- **What is unknown.** Efficacy of a real attacker against a real agent, live latency, and USD
  cost are unmeasured. That is why the slice is bounded and the flag waits.

**GCG is out of scope** for black-box agent scanning. It needs gradients from the target model's
weights, and ziran reaches a target only through `BaseAgentAdapter` text. It fits only a
self-hosted open-weight model with a gradient runtime; a transfer variant is offline vector
generation and belongs in its own item.

## Cost warning

> A PAIR vector is 10 to 100 times as expensive as a static vector. In the offline measurement one
> PAIR vector cost 20 to 34 times a static vector's tokens on average (11,906 and 19,738 against
> 589), and up to 65 times in the worst run. The bound is the iteration cap times the cost of one
> iteration (an attacker call, a target call and a judge call). The judge is about three
> quarters of each iteration. Set `max_iterations` and a campaign
> `--max-campaign-tokens` or `--max-cost` before enabling PAIR vectors.

This text goes into the vector docs and the executor's docstring in the first slice.

## How this fails

1. A live PAIR vector runs past the 60-second per-attack timeout and is cut off with no result.
   The slice gives a PAIR vector its own timeout and returns its best attempt.
2. A campaign budget is checked only between vectors, so one PAIR vector spends its whole
   iteration cap past the cap. The loop checks the budget before each iteration.
3. A deterministic attacker or a cassette keyed on the last turn sees a repeated request and
   loops. The spike hit this (6 of 20 runs succeeded); the request carries the iteration and the
   history.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a PAIR vector from the Python API (Priority: P1)

A security engineer gives `AgentScanner` an attacker client and a vector with `tactic: pair`. The
vector's first prompt is the seed prompt and its success indicators keep their meaning. The scan
refines the prompt until the pipeline calls it a success or a bound stops it.

**Why this priority**: it is the whole value of #275, and it reuses the scan, the detectors and
the report unchanged.

**Independent Test**: an offline unit test with a scripted attacker and a toy guarded target
reaches the secret in a known number of iterations.

**Acceptance Scenarios**:

1. **Given** a `tactic: pair` vector and an attacker client, **When** the target leaks the success
   indicator at iteration k, **Then** the `AttackResult` is successful, `prompt_used` is the
   iteration-k prompt, and evidence holds `pair.iterations == k` and `pair.stop == "success"`.
2. **Given** no attacker client, **When** a `tactic: pair` vector runs, **Then** the result is not
   successful and its `error` names the missing attacker; no target call is made.
3. **Given** the target never complies, **When** `max_iterations` is reached, **Then** the result
   is not successful, `pair.stop == "max_iterations"`, and `prompt_used` is the best-scoring
   attempt.

### User Story 2 - The bounds hold (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a campaign token cap, **When** the ledger reaches it mid-vector, **Then** the loop
   stops before its next iteration with `pair.stop == "budget"`.
2. **Given** a PAIR timeout, **When** it runs out mid-vector, **Then** the result carries the best
   attempt so far with `pair.stop == "timeout"`.
3. **Given** any run, **Then** attacker tokens are recorded under the `attacker` usage stage and
   judge tokens under `judge`.

### User Story 3 - A fixed seed replays (Priority: P2)

**Acceptance Scenarios**:

1. **Given** a scripted or replayed attacker and a fixed seed, **When** the vector runs twice,
   **Then** the two `pair.trajectory` lists are equal.

### Edge Cases

- The attacker reply is not JSON or has no `prompt`: count the iteration, record
  `attacker_parse_errors`, keep the last prompt.
- The attacker returns a `PendingResponse` (hybrid mode): stop with `pair.stop == "pending"`.
- The target raises or times out on one iteration: score it 0 and continue, as `AttackExecutor`
  does for a failed prompt.

## Requirements *(mandatory)*

- **FR-001**: `TacticType` gains `PAIR = "pair"`; `AttackExecutor` sends a `tactic: pair` vector to
  the PAIR executor, as it sends other tactics to `TacticExecutor`.
- **FR-002**: `AttackExecutor` takes an optional attacker `BaseLLMClient`; `AgentScanner` passes
  `scanner_config["attacker_llm_client"]`, wrapped by `track(..., "attacker")`.
- **FR-003**: Each iteration makes one attacker call, one `adapter.invoke` and one
  `DetectorPipeline.evaluate`. It stops on `verdict.successful`, and otherwise refines on
  `verdict.quality_score.composite_score` when present and on 0 or 1 when not.
- **FR-004**: Bounds: `max_iterations` (1 to 100, default 20), the campaign budget checked before
  each iteration, and a PAIR timeout. Each stop sets `pair.stop` to `success`, `max_iterations`,
  `budget`, `timeout` or `pending`.
- **FR-005**: The result's evidence holds `pair`: `iterations`, `stop`, `seed` and a
  `trajectory` of `{i, score, prompt_sha256}` (hashes, so a report never stores every attempt).
- **FR-006**: The attacker request holds the goal, the iteration number and the scored history,
  so no two requests in one stream repeat.
- **FR-007**: `usage.py` gains the `attacker` stage.
- **FR-008**: `AttackVector` gains an optional `pair: PairConfig` block (`max_iterations`, `seed`,
  `timeout_seconds`), validated like `many_shot`; a `tactic: pair` vector without it uses the
  defaults.
- **FR-009**: No new runtime dependency.

## Success Criteria *(mandatory)*

- **SC-001**: The offline unit tests cover each acceptance scenario above and pass on 3.11 to 3.13.
- **SC-002**: A scan with no `tactic: pair` vector is unchanged (existing tests pass untouched).
- **SC-003**: The cost warning above is in the docs and the executor docstring.

## Clarifications

### Session 2026-11-18

- Q: A new `AttackGenerator` port, as #275 sketches, or a tactic? → A: A tactic. The executor
  already dispatches on `tactic`, vectors stay YAML (constitution V), and a port with one
  implementation is a premature abstraction (constitution VI).
- Q: Which judge signal drives the loop? → A: Stop on `verdict.successful`; refine on the quality
  composite when the judge runs in quality mode; binary otherwise (research.md, judge signal).
- Q: Is the CLI flag in the first slice? → A: No. The Python API first; the flag waits for a live
  efficacy measurement.
- Q: Hybrid record-and-replay for the attacker in the first slice? → A: No. It costs N(N+1)/2
  target calls without a stream checkpoint (research.md, hybrid). The slice stops with `pending`
  if a hybrid attacker is given.
- Q: Parallel streams? → A: One stream in the first slice; cost scales linearly with streams.

## Smallest first build slice

| File | Change | Lines (est.) |
|---|---|---|
| `ziran/domain/entities/attack.py` | `PairConfig` and the vector's `pair` field, like `ManyShotConfig` | 20 |
| `ziran/application/attacks/pair.py` | new: `PairExecutor` | 125 |
| `ziran/application/attacks/tactics.py` | `TacticType.PAIR` | 1 |
| `ziran/application/agent_scanner/attack_executor.py` | attacker argument and dispatch | 15 |
| `ziran/application/agent_scanner/scanner.py` | pass the tracked attacker client | 5 |
| `ziran/application/usage.py` | `attacker` stage | 2 |
| `ziran/application/agent_scanner/phase_executor.py` | a PAIR vector's own timeout | 3 |
| `docs/concepts/attack-vectors.md` | cost warning and a `tactic: pair` example | 25 |
| `tests/unit/test_pair_executor.py` | new: scripted attacker, toy target, each scenario | 170 |

About 370 changed lines, one PR, under the 400-line batch. Plan: [plan.md](plan.md). Tasks:
[tasks.md](tasks.md).

## Assumptions

- The toy target and scripted attacker stand in for a live agent and attacker. They measure the
  loop's mechanics and cost shape, not efficacy. A live run with an owner key would overturn the
  success numbers, not the fit or the cost formula.
- Tokens are chars/4 estimates. Real tokenizer counts would shift the totals by a constant factor;
  the ratios and the judge share stay close.
- `PairConfig` lives on the vector (`pair:` block in YAML, like `many_shot:`). If owners want it
  scan-wide instead, it moves to `scanner_config` with no other change.
- The `tasks.md` build tasks are listed without checkboxes, since this PR stops before implement;
  only the spike's own tasks are checked.

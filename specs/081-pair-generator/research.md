# Research: does PAIR fit ziran, and at what cost per vector?

**Spec**: [spec.md](spec.md) | **Issue**: #275 | **Base**: `develop` @ c5d75eb | **Date**: 2026-11-18

All numbers below come from one offline prototype run. No model was called and no key was read.

## How the numbers were produced

```bash
uv run python specs/081-pair-generator/spike/pair_spike.py > specs/081-pair-generator/spike/result.json
```

The script is [spike/pair_spike.py](spike/pair_spike.py) and its output is
[spike/result.json](spike/result.json). It runs in under a second. A second run in a separate process,
compared with `diff` against the committed `result.json`, printed nothing.

What the prototype wires together, all from `develop` unchanged:

| PAIR role | ziran seam used | File |
|---|---|---|
| Attacker model | a `BaseLLMClient` (scripted, seeded) | `ziran/infrastructure/llm/base.py` |
| Attacker from a cassette | two `RecordReplayClient`s (spec 064, #491), one replaying and one recording | `ziran/infrastructure/llm/replay_client.py` |
| Target call | `BaseAgentAdapter.invoke`, the call `AttackExecutor` makes | `ziran/application/agent_scanner/attack_executor.py` |
| Scorer and stop rule | `DetectorPipeline.evaluate` with the LLM judge in quality mode (scripted judge) | `ziran/application/detectors/pipeline.py` |
| Token accounting | `UsageTrackingClient` on the attacker (stage `strategy`) and the judge (stage `judge`); target rows recorded the way `PhaseExecutor` does | `ziran/infrastructure/llm/usage_tracking_client.py`, `ziran/application/usage.py` |
| Budget | `CampaignBudget` with `UsageBudget(max_tokens=...)`, checked before each iteration | `ziran/application/usage.py` |

### The toy setup, and what it does not show

- **Target** (`ToyGuardAgent`): refuses any prompt holding `password`, `secret` or `credential`.
  Otherwise it leaks one line per framing cue present (role-play, auditor, JSON format). The third
  line holds the secret, which is the vector's success indicator. Two decoy framings never help.
  The tests' `MockAgentAdapter` could not serve: it is either always vulnerable or never, so a
  refinement loop has nothing to climb.
- **Attacker** (`ScriptedAttacker`): a pure function of (seed, request text). It toggles one of six
  edits on its last prompt, or on its best prompt after a score drop. A real attacker reads the
  response text; this one only reads the score. So the success rates measure the loop's
  mechanics and the value of the score signal, not how well an LLM attacker writes.
- **Judge** (`ScriptedJudge`): answers in the quality-judge JSON format, with specificity equal to
  the share of leak lines in the response. It is an oracle for the toy, so the graded signal is
  as clean as it can be. A real judge's discrimination is **unmeasured**.
- **Tokens**: the scripted clients report none, so `UsageTrackingClient` fills chars/4
  (`estimate_tokens`), flagged `estimated`. The judge's tokens are the real
  `_QUALITY_JUDGE_SYSTEM_PROMPT` plus the rendered message, so the judge share is realistic. The
  attacker system prompt is the spike's own short one; a production attacker prompt is longer,
  so the `strategy` share is a floor.
- **Data**: the goal, target and prompts are the spike's own. No prompt or goal from any benchmark
  set, and none from the ziran-paper held-out sets (specs 062, 065, 070).

## Measured results (50 seeds, 50-iteration cap)

### Iterations to success

| Score signal driving the loop | Successes / 50 | Median | Min | Max |
|---|---|---|---|---|
| Graded: judge quality composite (StrongREJECT) | 50 | 13 | 4 | 37 |
| Binary: pipeline `verdict.successful` only | 40 | 15 | 4 | 49 |

Source: `result.json` keys `graded_quality_signal.iterations_to_success`,
`binary_verdict_signal.iterations_to_success`.

### Tokens per vector

| | Graded | Binary |
|---|---|---|
| Mean tokens per vector | 11,906 | 19,738 |
| Max tokens per vector | 29,398 | 38,147 |
| Mean by stage: attacker (`strategy`) | 2,171 | 3,387 |
| Mean by stage: target | 635 | 1,004 |
| Mean by stage: judge | 9,099 | 15,347 |
| Tokens per iteration (attacker / target / judge) | 140 / 41 / 589 | 129 / 38 / 585 |
| Mean tokens per iteration | 770 | 752 |
| Ratio to one static vector (589 tokens) | 20.2x | 33.5x |

Source: `result.json` keys `*.tokens_per_vector`, `*.tokens_per_iteration_by_stage`,
`static_vector_tokens`, `cost_ratio_vs_static`. The static vector is one target call and one
quality-judge call on the base prompt, which is what `AttackExecutor` spends on a one-prompt vector
with the judge on. Worst runs cost 29,398 / 589 = 50x (graded) and 38,147 / 589 = 65x (binary).
Failed binary runs hit the cap, so their cost is the cap times the per-iteration cost.

The judge is 76 to 78 percent of every iteration (589 of 770; 585 of 752). The quality judge's
system prompt alone is most of it. Dropping the judge (binary signal, deterministic detectors
only) would leave about 170 tokens per iteration on the toy, but the judge is also what gives the
graded signal.

USD cost: **unmeasured**. The shipped price table (`ziran/infrastructure/llm/prices.yaml`) is
empty by rule (spec 047 adds no price without a cited source). With an operator price table the
ledger prices the `strategy` and `judge` stages; the target stage is never priced.

### Fixed-seed determinism

| Check | Result |
|---|---|
| Seed 7, run 1 trajectory sha256 (first 16) | `723bef712db61e80` |
| Seed 7, run 2 | `723bef712db61e80` (equal) |
| Seed 8 | `241261cc7431dfca` (differs) |
| Whole report, two separate processes | byte-identical |
| Seed 7 through the cassette vs direct | equal trajectory |

Source: `result.json` keys `determinism`, `hybrid_cassette.equals_direct_run`; the script asserts
both equalities and exits non-zero if either fails.

One design trap surfaced: the first version of the attacker request held only the last and best
prompts. A deterministic attacker then saw the same request twice and looped forever; only 6 of 20
graded runs succeeded. Adding the iteration number to the request (PAIR's real history grows each
step, so its requests never repeat) fixed it. A full build must key any cassette on the full
history, never on the last turn alone.

Determinism holds only offline. The live client (`ziran/infrastructure/llm/litellm_client.py`)
passes no `seed`, and PAIR's attacker samples at a high temperature by design. Live runs are not
reproducible; a replayed run is.

### Budget and iteration cap

| Check | Result |
|---|---|
| `max_tokens=1500` on seed 7 | stopped with `budget` after 3 iterations, at 2,195 tokens |
| 50-iteration cap | the 10 failed binary runs (50 minus 40 successes) stopped at the cap |

Source: `result.json` key `budget_cap_1500_tokens`. The check is cooperative, as in spec 047:
it runs before each iteration, so a run overshoots by at most one iteration (here 695 tokens).

### The hybrid cassette (#491) path

| Check | Result |
|---|---|
| Iterations to success, seed 7 | 13 |
| Record, send, replay rounds | 14 |
| Target invocations across all rounds | 91 (1 + 2 + ... + 13) |
| Trajectory equal to the direct run | yes |

Source: `result.json` key `hybrid_cassette`. It works without any change to ziran: a short
`ReplayThenRecord` composes a replaying and a recording `RecordReplayClient`, and a scripted sender
plays `hybrid_send` between rounds. Two costs show:

1. `RecordReplayClient` takes `record_to` or `replies`, never both. An iterative loop needs both
   (replay what was sent, record the next step), so a build adds a combined mode or composes the
   two as the spike does.
2. Each round reruns the stream from step 1, so the target is invoked N(N+1)/2 times for N
   iterations: 91 for 13, 1,275 for a 50-iteration cap. Against a live agent that repeats real
   tool calls. A hybrid PAIR needs a stream checkpoint, so each round invokes the target once.

## Which judge signal can drive the loop

- **The deterministic pipeline score is binary.** `DetectorPipeline._resolve` returns `score=0.0`
  or the deciding detector's score, and the indicator and refusal detectors score 0, 0.5 or 1.
  Every failed attempt therefore scores 0. It works as a stop rule and the loop still finds the
  toy secret in 40 of 50 runs, because the attacker keeps moving. It gives no direction.
- **The quality judge's composite is graded.** `QualityScore.composite_score`
  (`(1 - refusal) * (specificity + convincingness) / 2`) moves with partial leaks. With it the toy
  succeeded in 50 of 50 runs, at 40 percent fewer tokens per vector (11,906 vs 19,738). The
  pipeline returns `quality_score` on failed verdicts too, so the loop can read it from
  `evaluate()`.
- **`AttackExecutor.execute()` cannot be the loop's step as it stands.** On a failed vector it
  returns `quality_score=None` and evidence `{"note": ...}`, so the graded signal is lost. The loop
  calls `adapter.invoke` and `pipeline.evaluate` itself, the same two calls the executor makes.

**Chosen**: stop on `verdict.successful`, so a PAIR hit is a hit by the same rules as a static
vector. Refine on `verdict.quality_score.composite_score` when the judge runs in quality mode, and
fall back to the binary score when no judge is configured.

## Fit with the executor and the scan

- **Dispatch point exists.** `AttackExecutor.execute` already hands any vector whose `tactic` is
  not `single` to `TacticExecutor`. A `tactic: pair` vector can go to a PAIR executor the same way,
  so the YAML-driven vector model stays (constitution V) and no `advanced_generator` field is
  needed.
- **Attacker client.** `AttackExecutor` takes no LLM client today (`TacticExecutor(self._adapter)`).
  The build adds one constructor argument, passed from `scanner_config` the way `llm_client`
  reaches the pipeline.
- **Usage stage.** The spike used the existing `strategy` stage. A build adds an `attacker` stage
  to `Stage` and `STAGES` in `ziran/application/usage.py`, so reports split attacker cost from
  the adaptive strategy's.
- **Per-attack timeout.** `PhaseExecutor` wraps each vector in `asyncio.timeout(attack_timeout)`,
  60 seconds by default (`AgentScanner.DEFAULT_ATTACK_TIMEOUT`). A live PAIR vector makes three
  model or agent calls per iteration; 20 iterations will pass 60 seconds. This is code-derived,
  since live latency is **unmeasured**. A build gives a PAIR vector its own timeout and returns
  its best attempt when the time runs out.
- **Budget overshoot.** The campaign budget is checked between vectors. One PAIR vector can spend
  50 iterations at once, so the loop itself checks the budget before each iteration, as the spike
  does.

## GCG is out of scope for black-box agent scanning

GCG (Zou et al. 2023) needs the gradient of the target model's loss with respect to its input
tokens, which means the model's weights. ziran reaches a target only through `BaseAgentAdapter`
(text in, text and tool calls out), so no adapter can supply a gradient. GCG would need a
self-hosted open-weight model, a gradient runtime such as torch (a heavy optional dependency),
and a scan mode outside the agent seam. A transfer variant (optimise a suffix offline on an open
model, then ship it as a static YAML vector) is possible but is vector generation, not scanning,
and belongs in its own item.

## Not measured

- Efficacy of a real LLM attacker against a real agent: needs a key (owner).
- Live latency per iteration, and so the right PAIR timeout.
- A real judge's quality-score discrimination on partial compliance.
- USD per vector: needs priced models in an operator price table.
- Parallel streams: PAIR runs several streams; the spike ran one. Cost scales linearly with the
  stream count.

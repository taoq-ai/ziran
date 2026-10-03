# Long-running campaigns: checkpoint and resume

Comprehensive campaigns against large models can run for a long time. A single
phase at `--coverage comprehensive` can take tens of minutes. `ziran scan`
checkpoints its progress so an interrupted campaign (OOM kill, CI timeout,
laptop sleep, Ctrl-C) can pick up where it stopped instead of starting over.

## How checkpointing works

A checkpoint is a single JSON file at `<output-dir>/.checkpoint.json`. It records
the completed phases, the accumulated attack results, and the set of attack
vectors that have already been tested. Writes are atomic (temp file then
`os.replace`), so a crash mid-write never leaves a corrupt checkpoint: either the
previous checkpoint or the new one is present, never a truncated file.

Checkpointing is always on during a scan. The file is removed automatically when
a campaign completes successfully.

### Between-phase and partial-phase resume

The scanner checkpoints after every completed phase, and also incrementally
*within* a phase as individual vectors finish. That means a crash partway
through a long phase does not throw away the whole phase: on resume, the phase
re-enters and every vector already recorded in the checkpoint is skipped, so only
the not-yet-attempted vectors run.

## Resuming

Point `--resume` at the same `--output` directory the interrupted run used:

```bash
ziran scan --target ./target.yaml --coverage comprehensive --output ./run1
# ... process is killed partway through ...
ziran scan --target ./target.yaml --coverage comprehensive --output ./run1 --resume
```

If `--resume` is given but no checkpoint exists in the output directory, the scan
starts fresh with a warning.

## Tuning the flush interval

Incremental writes are throttled so the safety net does not become the
bottleneck: a checkpoint is flushed after a fixed number of completed vectors or
after a time interval, whichever comes first. The time interval is configurable:

```bash
ziran scan --target ./target.yaml --checkpoint-flush-interval 30
```

- Lower values (e.g. `5`) checkpoint more often. Resume loses less work after a
  crash, at the cost of more frequent writes.
- Higher values (e.g. `60`) reduce write frequency for very fast phases.
- Default: 10 seconds, with a completion-count backstop that also flushes
  periodically regardless of the interval.

Whatever the interval, at most the vectors completed since the last flush are
re-run on resume.

## Overhead

Building and atomically writing a checkpoint costs on the order of ~1 ms even for
a large campaign (hundreds of accumulated results). Because writes are throttled
rather than per-vector, the overhead stays well under the 5% budget for realistic
phases where each attack takes hundreds of milliseconds or more. In the
partial-phase resume integration test, flushing on *every* one of ten vectors
still completes the phase in well under a second.

## Token budget and cost cap

`ziran scan` records the tokens of every LLM call a campaign makes and can stop
the campaign when a token or cost cap is reached.

```bash
ziran scan --target ./target.yaml --llm-model gpt-4o \
  --max-campaign-tokens 200000 --max-cost 5 --output ./ziran_results
```

- `--max-campaign-tokens N` (integer, at least 1): cap on the tokens used across
  all stages, including the target.
- `--max-cost USD` (greater than 0): cap on the estimated cost. Only models with a
  price count towards it (see below).

The same limits are accepted by `AgentScanner` as the `scanner_config` keys
`max_campaign_tokens` and `max_cost`, together with an optional `usage_ledger`.

### Stages

| Stage | What it covers |
|---|---|
| `judge` | the single LLM judge (`--llm-model`), and ensemble members without their own `model` |
| `ensemble` | ensemble members with their own `model` (`.ziran/detectors.yaml`) |
| `prefilter` | the cheap first-pass judge (`prefilter.model`) |
| `strategy` | the `llm-adaptive` campaign strategy |
| `target` | the agent under test, as reported by its adapter; never priced |

### Where the numbers appear

- The **Campaign Summary** table gets one `Usage · <stage> · <model>` row per
  entry, an `All-Stage Tokens` row and an `Estimated Cost` row. It also says
  how many tokens have no price.
- The result JSON carries `metadata.usage`: `currency`, `entries` (stage, model,
  calls, prompt/completion/total tokens, `estimated_calls`, `cost_usd`),
  `total_tokens`, `total_cost_usd`, `unpriced_tokens`, `max_campaign_tokens` and
  `max_cost_usd`.
- When a cap stopped the campaign, `metadata.status` is `budget_exceeded` and the
  summary shows `Status: BUDGET EXCEEDED (partial results)`. The key is absent
  otherwise.
- `token_usage` on the result keeps its old meaning: target tokens only.

### Prices

Costs are estimates: tokens multiplied by list prices, in USD per 1,000,000
tokens. The shipped table (`ziran/infrastructure/llm/prices.yaml`) holds only
prices copied from a provider's public pricing page, each with a cited source; it
currently ships empty. Add your own in `.ziran/prices.yaml` in the working
directory. Its entries are merged over the shipped ones, model by model:

```yaml
version: 1
currency: USD
models:
  gpt-4o:            # the model name you pass with --llm-model
    input_per_mtok: <USD per 1M prompt tokens>
    output_per_mtok: <USD per 1M completion tokens>
```

A model is looked up by its exact name first, then by the part after the last
`/` (`openai/gpt-4o` falls back to `gpt-4o`). An invalid file stops the scan with
exit code 1 (`invalid price table .ziran/prices.yaml: ...`).

A model without a price has `cost_usd: null`, never `0`. Its tokens are counted
in `unpriced_tokens` and do not count towards `--max-cost`. With `--max-cost`
set, the scan prints a warning for each tracked model that has no price. The
target stage is never priced.

When a provider reports 0 prompt or completion tokens, the count is estimated as
characters / 4 and the call is counted in `estimated_calls`.

### The cap is cooperative

The budget is checked before each attack vector starts (after it gets a
concurrency slot) and before each phase. Attacks already running finish and all
their judge calls are recorded, so the final total can go past the cap by up to
`--concurrency` attacks' worth of tokens. A multi-prompt vector is never cut in
the middle. Reaching the cap exactly counts as reached.

When the cap is hit, ziran stops scheduling attacks and skips the post-attack
utility measurement. It still writes the partial result and keeps the checkpoint,
which now also stores the usage ledger. To continue, re-run with `--resume` and
a higher cap (or none):

```bash
ziran scan --target ./target.yaml --llm-model gpt-4o \
  --max-campaign-tokens 400000 --resume --output ./ziran_results
```

The resumed run skips the vectors already tested. It re-enters the phase that
was cut short and adds the restored usage to its totals. Resuming with the same
cap stops again right away and leaves the checkpoint as it is. The exit code of
a budget-stopped scan is 0.

### Limitations

- The `strategy` stage records nothing for now: `LLMAdaptiveStrategy` calls
  `asyncio.run` inside the running event loop, which fails before the client is
  called.
- Target tokens are what the adapter reports. Adapters that report none
  contribute 0, and no estimate is applied to the target.
- Calls cancelled by a timeout or failing in the provider are not recorded.
- Semantic-tier embedding calls, utility tasks, pentest and web UI budgets are
  not tracked.
- After a mid-phase stop, the resumed run's result for that phase lists only the
  vulnerabilities found after the resume. The earlier ones remain in
  `attack_results`. Crash resume behaves the same way.

## Notes

- Checkpoints written by older versions (between-phase only) still load and
  resume: the file format is unchanged, and partial resume rides the existing
  `tested_vector_ids` field.
- Token totals in a mid-phase checkpoint may slightly undercount the in-progress
  phase; the count is corrected at phase completion. This does not affect which
  vectors are skipped on resume.

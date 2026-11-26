# Spec 121: repeat trials per vector

**Status**: Active

## Promise (in my words)

`ziran scan --trials k` (default 1; the scanner config key `trials`) runs every attack vector k times. The target is reset with the adapter's `reset_state()` before each run after the first. The vector's result records how many of the k runs succeeded, pass@k (at least one run succeeded) and pass^k (every run succeeded). SARIF and the Markdown and HTML reports mark a finding flaky when some runs succeed but not all. The incremental scan cache keeps each run under its own key. With k = 1 nothing changes: the same calls, the same result object, the same files and output.

## Acceptance

- A scripted target complies on runs 1 and 3 of 3. With `--trials 3` the vector reads 2 of 3 and flaky, and its SARIF result has `properties.success_rate` 0.67.
- With `--trials 1` (or no flag) the stored result is the executor's own object, the executor is called once with today's arguments, no reset happens, and SARIF and the reports carry no trial field. The existing scan, SARIF, report and cache tests pass unchanged.

## Behaviour

- The vector is successful when any run succeeded (pass@k). The first successful run's result carries the evidence, goal verdict and response; with no success, the last run's.
- `evidence["trials"]` = `{k, successes, success_rate (2 decimals), pass_at_k, pass_hat_k, flaky, outcomes}`.
- Token usage and probe markers add up over all runs.
- Each run has its own side-effect goal turns (spec 116) and its own probe-marker trace: run 1 keeps today's `campaign/vector` scope, run N > 1 uses `campaign/vector/trial-N`.
- Cache: run 1 keeps `<vector_id>.json` and its key; run N+1 uses `<vector_id>~trialN.json` with the trial index in its key. `~` is not a legal vector id character, so a run file never names another vector.
- `trials < 1` is refused (CLI exit 2; `PhaseExecutor` raises `ValueError`).

## Consumers checked

Phase executor (records, graph, artifacts, budget ledger), checkpoint and resume (per vector, unchanged), scan cache, SARIF `_build_result`, Markdown findings list, HTML vulnerability cards, `campaign_from_sarif` (ignores the new properties), PAIR `run_in_phase` (gets the trial through a partial), OTel attack metrics (one record per run).

## Assumptions

- `reset_state()` acts on the shared adapter, as the two-session tactic already does mid-attack. With `--concurrency` above 1 a reset between runs can clear another vector's conversation on adapters that keep one. Overturn if a multi-turn result changes with concurrency; then run trials with `--concurrency 1` or per-attack sessions.
- A run that times out loses the vector, as a single timed-out run does today. Overturn if partial k-of-N on timeouts is asked for.
- pass@k and pass^k per vector are booleans: with n = k samples the unbiased pass@k estimator is 1 when any run succeeded, and pass^k is 1 only when all did. A campaign-wide rate is not added here.
- `ScanCacheStats.executed` counts runs, not vectors, when k > 1.

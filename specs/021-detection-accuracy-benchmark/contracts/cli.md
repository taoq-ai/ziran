# Contract: Benchmark CLI

The detection-accuracy harness is invoked as a benchmark script, consistent with the existing `benchmarks/*.py` entry points (e.g. `regression_check.py`).

## `benchmarks/detection_accuracy.py`

```text
uv run python benchmarks/detection_accuracy.py [OPTIONS]
```

| Option | Type | Default | Behaviour |
|--------|------|---------|-----------|
| `--json PATH` | path | `benchmarks/results/detection_accuracy.json` | Write `DetectorAccuracyResult` JSON. |
| `--config PATH` | path | `.ziran/detectors.yaml` if present, else built-in defaults | Threshold config to apply to the pipeline. |
| `--dataset PATH` | path | `benchmarks/ground_truth/detection/` | Labelled dataset root. |
| `--by-category` | flag | off | Also print per-category breakdown. |
| `--format {table,markdown}` | enum | `table` | Human-readable output style. |

**Exit code**: `0` on success; non-zero on dataset validation failure (missing label/response, malformed YAML) with a message identifying the offending file (spec edge case).

**Stdout**: per-detector and pipeline precision / recall / F1 (+ Wilson CI) and confusion matrix; a coverage line confirming ≥50/category.

## `benchmarks/detection_regression.py`

```text
uv run python benchmarks/detection_regression.py [OPTIONS]
```

| Option | Type | Default | Behaviour |
|--------|------|---------|-----------|
| `--baseline PATH` | path | `benchmarks/results/detection_accuracy_baseline.json` | Baseline to compare against. |
| `--update-baseline` | flag | off | Recompute and overwrite the baseline (explicit, reviewed action — FR-010). |
| `--format {table,markdown}` | enum | `table` | Output style. |

**Gate semantics (Q3)**: fail (exit non-zero) iff `baseline.pipeline_f1 - current.pipeline_f1 > baseline.tolerance` (default `0.02`). Per-detector F1 deltas are printed but never cause failure.

**Exit codes**: `0` pass; `1` regression beyond tolerance; `2` baseline missing (instructs running with `--update-baseline`).

## CI integration

A required (blocking-on-`main`) workflow job runs `detection_regression.py` on pull requests. To avoid the branch-protection deadlock that a `paths:`-filtered required check causes (the check never reports on unrelated PRs, blocking merge forever), the job **always runs** but detects changed paths *inside* the job: if the diff touches `ziran/application/detectors/**`, the dataset, or threshold files, it runs the gate; otherwise it short-circuits and reports success.

## Backwards-compatibility guarantee

With no `--config` and no `.ziran/detectors.yaml`, `DetectorThresholds()` defaults reproduce the current pipeline behaviour exactly. No existing public API signature is removed; `DetectorPipeline.__init__` only *gains* an optional threshold carrier via `DetectorConfig`.

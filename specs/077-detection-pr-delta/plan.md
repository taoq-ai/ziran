# Implementation Plan: detection-accuracy PR comment and recall gate

**Branch**: `ci/077-detection-pr-delta` | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ ede6cc6

## Summary

Extend `benchmarks/detection_regression.py` with a metric snapshot (precision, recall, F1, FPR,
confusion), two new gate rules on pipeline recall and FPR, and a markdown comment renderer. In
`.github/workflows/detection-accuracy.yml`, score the PR base code on the head dataset, pass that
result to the gate's comment, upload the comment, and post it from a second job that alone holds
`pull-requests: write`.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13); GitHub Actions YAML and bash.
**Primary Dependencies**: Pydantic v2, stdlib `argparse`/`pathlib`; `actions/upload-artifact@v7`
and `actions/download-artifact@v8` (both already used in this repository); `gh api`. No new
dependencies.
**Storage**: committed `benchmarks/results/detection_accuracy_baseline.json`; CI-only files under
`$RUNNER_TEMP`.
**Testing**: pytest, `@pytest.mark.unit` tests in `tests/unit/test_detection_regression_gate.py`
on the comparison, threshold and renderer functions; the existing integration tests in
`tests/integration/test_detection_regression.py` keep running.
**Constraints**: `benchmarks/` is outside `mypy ziran/` but under `ruff`; annotate anyway.

## Constitution Check

- Hexagonal architecture: no change under `ziran/`.
- Type safety: Pydantic model for the snapshot; annotated functions.
- Tests: unit tests carry `@pytest.mark.unit`; test first.
- Simplicity: one model, three functions, two flags; no new dependency.

## Code trace (develop @ ede6cc6)

- `detection_regression.main()` runs `run_benchmark(args.dataset)` (built-in thresholds), loads
  `DetectionAccuracyBaseline`, sets `regressed = baseline.pipeline_f1 - f1 > tolerance`, prints
  `_render(...)`, exits 1 on regression.
- `detection_accuracy.DetectorMetrics` holds `confusion`, `precision`, `recall`, `f1`; FPR is
  derived as `fp / (fp + tn)`.
- The workflow's `changed` step greps the diff against a path regex and sets `relevant`.

## Public contract

`benchmarks/detection_regression.py`:

- `MetricSnapshot(precision, recall, f1, fpr, confusion)`, with `MetricSnapshot.of(DetectorMetrics)`.
- `PIPELINE = "pipeline"`, `COMMENT_MARKER = "<!-- ziran-detection-accuracy -->"`.
- `DetectionAccuracyBaseline` gains `pipeline: MetricSnapshot | None = None` and
  `per_detector: dict[str, MetricSnapshot] = {}`, plus `snapshots()`.
- `result_snapshots(DetectorAccuracyResult) -> dict[str, MetricSnapshot]`, keyed by detector name
  plus `PIPELINE`.
- `gate_failures(baseline, result) -> list[str]`: empty means pass.
- `render_comment(head, base, failures, *, base_note) -> str`.
- CLI: `--comment PATH`, `--base-result PATH`. Exit codes unchanged (0, 1, 2).

Workflow:

- Job `detection-accuracy-gate` (name unchanged, `contents: read`), output `relevant`.
  New PR-only steps: `base` (git archive of `github.event.pull_request.base.sha` into
  `$RUNNER_TEMP/detection_base`, run its `benchmarks/detection_accuracy.py --dataset
  benchmarks/ground_truth/detection --json $RUNNER_TEMP/detection_base.json`,
  `continue-on-error`); the gate step adds `--comment` and, when `base` succeeded,
  `--base-result`; an `always()` upload of `$RUNNER_TEMP/detection-comment/`.
- Job `detection-accuracy-comment` (`needs` the gate, `if: always()` on relevant PRs,
  `pull-requests: write` only): download the artifact, append the base SHA, find the bot comment
  that starts with the marker through `gh api`, PATCH it or POST a new one. Both steps
  `continue-on-error`.

## Comment layout

```
<!-- ziran-detection-accuracy -->
### Detection accuracy: head vs base

**Gate: pass** (or **Gate: FAIL** and one bullet per failing rule)

| detector | TP/FP/FN/TN | precision | recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- |
| refusal | 52/12/0/52 (=) | 0.8125 (=) | ... |
| **pipeline** | ... |

Each cell is the head value; `(=)` means base is the same, otherwise `(base X, +d)`.
<base note>
Gate rules (vs the committed baseline): ...
```

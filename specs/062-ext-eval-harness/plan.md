# Implementation Plan: external benchmark harness for the response detectors

**Branch**: `feat/062-ext-eval-harness` | **Date**: 2026-10-29 | **Spec**: [spec.md](spec.md)

## Summary

A stand-alone package under `benchmarks/external_eval/`. The parent process (`run.py`) does
intake, mapping and metrics and never imports `ziran`. For each pin it exports the pinned tree
with `git archive` into a fresh temporary folder and runs `worker.py` there under `python -I`,
with an allow-listed environment and an empty working folder. The worker imports only the
standard library and the export, scores every unit with `DetectorPipeline(DetectorConfig())`,
and checks that every loaded `ziran` module resolves inside the export.

## Technical Context

- **Language**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
- **Dependencies**: none new. Standard library (`zipfile`, `csv`, `hashlib`, `tarfile`,
  `statistics`, `random`, `sys.addaudithook`) and Pydantic v2, already a dependency.
- **Testing**: pytest, `@pytest.mark.unit`. Hand-made fixtures built in the tests; the
  end-to-end tests export the current commit as the pin.
- **Scope**: the new package, four test files, one `.gitignore` line, this spec. No change
  under `ziran/`.

## Constitution Check

- Hexagonal: benchmark tooling outside the `ziran` package, like `benchmarks/detection_accuracy.py`.
  It uses the application layer's public `DetectorPipeline` and changes no layer. PASS
- Type safety: annotated throughout; `mypy --strict` passes on the package; Pydantic models for
  units, manifest, proportions and the collected set. PASS
- Tests: unit tests for intake, mapping, the evaluator copy, metrics and isolation, plus two
  end-to-end runs. PASS
- Async-first: the worker awaits `DetectorPipeline.evaluate` in one event loop; the CLI entry is
  the only sync wrapper. PASS
- Simplicity: one module per protocol concern; no new dependency; no change to the detectors.
  PASS

## Design

| Module | Protocol | Role |
| --- | --- | --- |
| `intake.py` | 9 | errors, manifest, `load` (sha256 before parse, section 1 hashes), `open_zip` and `read_member` (limits, unsafe names, symlinks), `spdx_id`, `require_fields`, JailbreakBench target check, git-ignore check |
| `mapping.py` | 2, 4, 5, 7 | split filters and one `Unit` per row variant: AgentDojo whole, post-injection and text-only; InjecAgent whole and text-only; JailbreakBench; HarmBench |
| `injecagent_eval.py` | 9 | reviewed copy of `evaluate_output_prompted` and the functions it calls |
| `collect.py` | 9 checks 1 to 6 | hash every listed file, check licences and terms, build units, tally counts |
| `metrics.py` | 6, 7 | Wilson proportions, X1 to X4, cluster bootstrap |
| `isolation.py` | 4, 9 | interpreter flags, environment scrub and allow-list, pin export, file hashes, harness record |
| `worker.py` | 4 | the per-pin scorer; stdlib and the export only |
| `run.py` | all | CLI; writes `<benchmark>.rows.jsonl` and `<benchmark>.summary.json` |

Worker protocol: stdin JSON lines `{key, prompt, content, tool_calls}`; stdout a header with the
pin's `DetectorThresholds()` and `DetectorConfig()` dump and module count, one
`{key, refusal, side_effect, pipeline}` line per unit, and an end line with the count. The
parent checks order and count. Worker stderr is captured and not printed.

Exit codes: 0 evaluated; 2 refused (flags, paths, pins, worker); 3 not evaluated (intake failed,
protocol section 10), with the reason in the summary.

## Risks

- Unread layouts (`results.zip`, the HarmBench validation set) are assumptions in the spec. A
  mismatch shows as an intake failure; it must be checked against the intake listing before the
  addendum freezes the harness commit.
- The worker scores excluded units too, so their rows carry verdicts next to the exclusion
  reason; metrics use analysed units only.

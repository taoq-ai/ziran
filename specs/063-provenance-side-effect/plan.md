# Implementation Plan: argument provenance in the side-effect detector

**Branch**: `feat/063-provenance-side-effect` | **Spec**: [spec.md](spec.md)

## Summary

One new application module, `ziran/application/detectors/provenance.py`, holds the runbook's
name typing and value matching (ported from the frozen dev probe, `g10_dev_probe.py` at
`f80204a6`, lines 66 to 225) and the T3/P1 first pass with its evidence record.
`SideEffectDetector.detect` calls it first; when the result is `not_applicable` the study-v1 code
path runs unchanged, otherwise the rule's verdict is returned.

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2 for the record (`CallEvidence`,
`Provenance`, frozen). Stdlib `re` and `json`. No new dependency. No model call.

## Constitution check

- Hexagonal: the module is application layer and imports only the domain (`tool_classifier`,
  `AgentResponse`, `AttackVector`).
- Type safety: annotated, mypy strict clean, Pydantic models for the record.
- Tests: unit tests for the rule and record; integration tests over the detection dataset.
- Simplicity: one module, one call site; no new config, threshold or option.

## Files

| File | Change |
| --- | --- |
| `ziran/application/detectors/provenance.py` | new: verbs, typing, matching, `provenance()` |
| `ziran/application/detectors/side_effect.py` | call `provenance()` first; result for a known task or payload |
| `benchmarks/ground_truth/schema.py` | `DetectionExample.metadata`, `ToolCallRecord.message_index` |
| `benchmarks/detection_accuracy.py`, `benchmarks/two_tier_judging.py` | pass `metadata`; dump tool calls with `exclude_none` so study-v1 items keep their inputs |
| `benchmarks/ground_truth/detection/generate_dataset.py` | `gen_benign_task`: six items |
| `benchmarks/ground_truth/detection/full_compliance/det_full_compliance_053..058.yaml` | generated |
| `benchmarks/results/detection_accuracy_baseline.json` | rebuilt: 228 items |
| `tests/fixtures/detection/study_v1_verdicts.json` | study-v1's verdict on the 222 items |
| `tests/unit/test_side_effect_provenance.py`, `tests/integration/test_detection_study_v1_equality.py` | new |
| `docs/concepts/detection-pipeline.md`, `docs/reference/benchmarks/detection-accuracy.md`, `CLAUDE.md` | the inputs, the new items, the counts |

Frozen and untouched: `ziran/domain/tool_classifier.py`, `ziran/application/detectors/refusal.py`,
`ziran/application/detectors/llm_judge.py`, `ziran/domain/entities/claude_code.py`. Section
13 of the protocol lists only ziran-paper files; none is in this repository.

## The study-v1 fixture

Written from the tag itself, never from this branch:

```bash
git -C <ziran> archive study-v1 ziran benchmarks | tar -x -C <scratch>/v1
PYTHONPATH=<scratch>/v1 <worktree>/.venv/bin/python v1_verdicts.py <scratch>/v1/ziran \
  tests/fixtures/detection/study_v1_verdicts.json
```

`v1_verdicts.py` builds the benchmark's pipeline (`ReplayLLMClient`, single judge, default
thresholds), asserts that `ziran` loads from the export, and writes per `example_id` the verdict's
`successful`, `score`, `reasoning` and each detector's name, score and confidence. study-v1 and
`develop` hold the same detector code and dataset (`git diff --stat study-v1 origin/develop --
benchmarks/ground_truth/detection ziran/application/detectors ziran/domain/tool_classifier.py` is
empty), so the 222 items are the dataset as at study-v1.

## Parity with the dev probe

A scratch check ran `provenance()` and the frozen probe's `t3`/`p1` on 3,000 random synthetic
AgentDojo-shaped logs (one user message, one injection): 0 differences on either rule, with 886 T3
hits and 1,860 P1 hits. Two input differences are by protocol: the task is the first user message
(the probe joins all user messages), and payload strings are matched one by one (the probe joins
them with a space).

`tests/unit/test_provenance_probe_parity.py` pins this in the repository: a copy of the probe's rule code as the oracle, 400 seeded synthetic logs, both rules equal on every log.

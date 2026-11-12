# Implementation Plan: the fresh AgentDojo set and the provenance inputs in the harness

**Branch**: `feat/065-harness-fresh` | **Spec**: [spec.md](spec.md)

## Summary

The mapping builds the section 5 keys from each AgentDojo log and checks them at intake. The
worker passes them to the pinned detector in `AgentResponse.metadata` and reports
`provenance(...).hit` as the `deterministic` predictor where the pin has it. The run turns a
`ProvenanceInputError` into a `detector_raised` exclusion at every pin, then writes one
allowlisted row per unit.

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Stdlib `re` and `json`; Pydantic v2 (`Unit`).
No new dependency, no model call, no git call in the worker.

## Constitution check

- Hexagonal: the harness stays outside `ziran/`. The one `ziran/` change (the HTTP adapter's
  metadata filter) is infrastructure and imports nothing new.
- Type safety: annotated; `mypy ziran/` strict clean.
- Tests: unit and end-to-end tests on hand-made logs; the dev replay on the iterate split.
- Simplicity: no new module in the harness; one new benchmark key reuses the AgentDojo builder.

## Files

| File | Change |
| --- | --- |
| `benchmarks/external_eval/mapping.py` | path regex takes any attack; `agentdojo_fresh_admitted`; the section 5 keys; tool-message matching and the two other intake checks; payload variants; `INVALID_REASONS` |
| `benchmarks/external_eval/collect.py` | `agentdojo_fresh` builder and primary (`deterministic`) |
| `benchmarks/external_eval/worker.py` | metadata from the three keys; `deterministic`; `raised` on `ProvenanceInputError` |
| `benchmarks/external_eval/run.py` | `check_row`; one row per unit; the raise rule; predictors a pin lacks are skipped; pin names checked |
| `ziran/infrastructure/adapters/http_adapter.py` | drop `trusted_task`, `tool_results`, `payload` from remote metadata |
| `tests/unit/test_external_eval_fresh.py` | new: include rule, keys, intake checks, row allowlist, three end-to-end runs |
| `tests/unit/test_external_eval_{mapping,run}.py`, `tests/unit/test_http_adapter.py` | the old row and call shapes updated; the strip test |
| `specs/065-harness-fresh/{fetch_iterate,dev_replay}.py` | the replay, kept for the gates to rerun |

## The dev replay

1. `fetch_iterate.py` filters the G-9 manifest to the iterate side with `g11_dev_sets.side`,
   passes the list through `g11_dev_sets.guard(lockbox=False)` (which refuses any lockbox
   path), and fetches those 9,912 logs and the licence with the probe's own `fetch`, sha256
   checked.
2. The harness runs on that download at `study-v1` and at the branch commit.
3. `dev_replay.py` compares the study-v1 rows with the committed G-9 rows, and the patched
   `deterministic` verdicts with the probe's `t3` and `p1` on each log. It prints counts only.

The download stays in a scratch folder outside the repository and is deleted after the run.

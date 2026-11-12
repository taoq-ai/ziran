# Implementation Plan: the AgentDojo reserve set and the `run.py --paper` guard check

**Branch**: `g11-agentdojo-reserve` | **Spec**: [spec.md](spec.md)

## Summary

The reserve set reuses the AgentDojo builder with its own include rule and a unit function that
adds the `attack` cell. `run.py` gains `--paper` and `require_admitted`, which reads the set's use
log in the paper checkout before the run writes or reads anything.

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Stdlib `json`; one `git show` through `isolation.git_show`, which wraps the harness's
existing `isolation._git` (lazy fetch off). No new dependency, no model call, no ziran-paper code
imported.

## Constitution check

- Hexagonal: the harness stays outside `ziran/`; no `ziran/` file changes.
- Type safety: annotated; `mypy ziran/` strict clean, and the four harness modules clean.
- Tests: unit and end-to-end tests on hand-made logs and synthetic use logs, each guard check run
  as its own refusal, and a mutant pass on the new code.
- Simplicity: no new module; one benchmark key, one rule, one unit wrapper, one check function.

## Files

| File | Change |
| --- | --- |
| `benchmarks/external_eval/mapping.py` | `is_run_log`, `agentdojo_reserve_admitted`, `agentdojo_reserve_units` |
| `benchmarks/external_eval/collect.py` | `_agentdojo` takes the unit function; `agentdojo_reserve` builder and primary |
| `benchmarks/external_eval/isolation.py` | `git_show` |
| `benchmarks/external_eval/run.py` | `USE_LOGS`, `--paper`, `require_admitted` before the output folder |
| `tests/unit/test_external_eval_reserve.py` | include rule, attack cell, end to end, every refusal |
| `tests/unit/test_external_eval_run.py` | `paper_checkout` and `aborted` helpers; `run_cli` passes `--paper` for a guarded set |
| `tests/unit/test_external_eval_fresh.py`, `test_external_eval_mapping.py` | old-contract updates: `--paper` on the pair run, the primary table |

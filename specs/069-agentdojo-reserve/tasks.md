# Tasks: the AgentDojo reserve set and the `run.py --paper` guard check

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Write `tests/unit/test_external_eval_reserve.py`: include rule, disjointness, attack cell, end to end, each refusal, refusal before any data read
- [x] T002 Add `paper_checkout` and `aborted` to `tests/unit/test_external_eval_run.py`; pass `--paper` in the fresh pair-run test
- [x] T003 Run red (no `agentdojo_reserve_admitted`, no `agentdojo_reserve` choice, no `--paper`)

## Phase 2: implementation

- [x] T004 `mapping.py`: `is_run_log`, `agentdojo_reserve_admitted`, `agentdojo_reserve_units`
- [x] T005 `collect.py`: the `agentdojo_reserve` builder and primary
- [x] T006 `run.py` and `isolation.py`: `--paper`, `USE_LOGS`, `require_admitted`, `git_show`
- [x] T007 Update the old-contract primary-table test

## Phase 3: checks and records

- [x] T008 Run the suite with an empty HOME and stubbed model CLIs; ruff, ruff format, mypy
- [x] T009 Run mutants on the new code against the reserve tests
- [x] T010 Add the spec line to `CLAUDE.md` Recent Changes
- [x] T011 Fix round (quality and security at 76c787f): HEAD-not-index test, top-level and on-`main` checks, field checks before the manifest, the exit-2 manifest test

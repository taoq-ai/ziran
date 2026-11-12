# Tasks: the fresh AgentDojo set and the provenance inputs in the harness

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Write `tests/unit/test_external_eval_fresh.py`: include rule, section 5 keys, intake checks, row allowlist, end-to-end runs
- [x] T002 Add the HTTP adapter strip test to `tests/unit/test_http_adapter.py`
- [x] T003 Run both red (`check_row` missing; the adapter keeps the keys)

## Phase 2: implementation

- [x] T004 `mapping.py`: any-attack path, `agentdojo_fresh_admitted`, the keys, the three intake checks, payload variants
- [x] T005 `collect.py`: the `agentdojo_fresh` builder and primary
- [x] T006 `worker.py`: metadata from the three keys, `deterministic`, `raised`
- [x] T007 `run.py`: `check_row`, one row per unit, the raise rule, pin names
- [x] T008 `http_adapter.py`: drop the three keys from remote metadata
- [x] T009 Update the old-contract tests (row shape, `message_index` on calls, five variants)

## Phase 3: checks and records

- [x] T010 Dev replay on the iterate split: study-v1 against the committed rows, deterministic against the probe
- [x] T011 ruff check, ruff format, mypy strict, the full test suite with coverage
- [x] T012 Record the change in `CLAUDE.md`

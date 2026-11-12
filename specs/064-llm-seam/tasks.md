# Tasks: prompt registry and record-and-replay model client

**Input**: [spec.md](spec.md), [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Placeholder prompts, one per job, in `tests/fixtures/hybrid_prompts/<job>/v0.md`
- [x] T002 Registry tests (load, sha256, refused names, base-branch immutability) in `tests/unit/test_hybrid_prompts.py`
- [x] T003 Key, record and replay tests (acceptance 1 and 2, edge cases, planted log marker) in `tests/unit/test_replay_client.py`
- [x] T004 Routing and decide tests (acceptance 3, share 0.0, order, refusals) and the import isolation test (acceptance 4) in `tests/unit/test_hybrid_decide.py`
- [x] T005 Run the new tests red

## Phase 2: implementation

- [x] T006 `ziran/application/hybrid/prompts.py`
- [x] T007 `ziran/infrastructure/llm/replay_client.py`
- [x] T008 `ziran/application/hybrid/__init__.py`
- [x] T009 Fetch `develop` in the CI test job so the immutability test runs

## Phase 3: checks

- [x] T010 Run the new tests green; ruff, ruff format, mypy, the full unit suite
- [x] T011 Detection regression and benchmark regression check on the branch (acceptance 4)
- [x] T012 Update `CLAUDE.md` with `update-agent-context.sh`

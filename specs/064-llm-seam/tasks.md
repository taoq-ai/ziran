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
- [x] T009 Fetch the run's base (PR base branch or pushed-over commit) in the CI test job so the immutability test runs

## Phase 3: checks

- [x] T010 Run the new tests green; ruff, ruff format, mypy, the full unit suite
- [x] T011 Detection regression and benchmark regression check on the branch (acceptance 4)
- [x] T012 Update `CLAUDE.md` with `update-agent-context.sh`

## Phase 4: fix round 1 (gates at ed7cd8f)

- [x] T013 Refuse symlinks at the request path and its parents; open with O_NOFOLLOW, owner-only
- [x] T014 Immutability base from ZIRAN_PROMPT_BASE; fail in CI when unfetched
- [x] T015 decide(): band units only, job-supplied merge, llm_pending maps unit to cause
- [x] T016 PendingResponse in infrastructure/llm/base.py; outcome classes whitelisted; bool share refused
- [x] T017 Tests: rounding pins, pending guard, goal probes A and B, import guard forms, symlinks
- [x] T018 `*.requests.jsonl` in .gitignore; merge develop

## Phase 5: fix round 2 (gates at da86051)

- [x] T019 Immutability base has no default: unset skips, set but unfetched fails; test the branch
- [x] T020 Test every sender outcome class through replay
- [x] T021 Resolve folders above the request folder; hold the folder open and use dir_fd
- [x] T022 fstat check: regular file, one link; O_NONBLOCK so a FIFO cannot block; tests

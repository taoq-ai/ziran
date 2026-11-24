# Tasks: aim chain vectors at the lethal trifecta, refuse credential files, swap whole host names

Base: `origin/develop` @ dfdbe96. Branch `feat/096-steer-trifecta`. Test first: T002 runs red
before T003.

## Phase 1 - Check and tests

- [x] T001 Count the library vectors the wider path check newly skips (FR-006): 0 at standard.
- [x] T002 Tests in `test_chain_targeting.py` and `test_tool_aliases.py`, run red (11 failing).

## Phase 2 - Change

- [x] T003 `tool_aliases.py`: public `SECRET_PATH` with `/etc/shadow` (FR-004).
- [x] T004 `chain_targeting.py`: `trifecta` prefix, `_leg` ends, mail task (FR-001 to FR-003).
- [x] T005 `chain_targeting.py`: path tokens in `_names_secret`, anchored `swap` (FR-004, FR-005).
- [x] T006 Review the six-tool agent's new prompts by hand and update the `CHOSEN` pins.

## Phase 3 - Proof

- [x] T007 Touched tests and `test_scanner_size.py` green; ruff and strict mypy clean.
- [x] T008 Mutants in a `git archive` copy.

## Phase 4 - Fix round 1

- [x] T009 `test_langgraph_adapter.py`: the strategy context holds every target's ids in order.
- [x] T010 `swap` longest host first again; test with nine host and host:port pairs.
- [x] T011 Path tokens read `\` as `/`; Windows, quote, backtick, bracket and separator tests.
- [x] T012 Trifecta source prefers a tool without a secret word; legs from `trifecta.LEGS`; mail
      check tested on `SendMail` and `mailer`.

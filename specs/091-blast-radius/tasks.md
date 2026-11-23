# Tasks: blast radius per chain, demonstrated vs reachable, with what-if

Base: `origin/develop` @ 7006a23. Branch `feat/091-blast-radius`. Test first: T001 runs red
before T002.

## Phase 1 - Tests (US1 to US4)

- [x] T001 `tests/unit/application/test_blast_radius.py`: the flat scan with demonstrated file
      source and external egress, an untouched chain, malformed calls, what-if from both tools
      with the graph unchanged, an unknown removed id, delegation down and not up, shared
      context against trust boundaries, the name rules and overrides both ways, a bad override,
      the list cap with full counts, and hostile tool lists at 100 and 101 tools and
      20,000-character ids.

## Phase 2 - Implementation (FR-001 to FR-006)

- [x] T002 `capability.py`, `phase.py`: `BlastReach`, `BlastRadius`, the chain and result fields.
- [x] T003 `blast_radius.py`: the walk, the split, `is_external`, the cap.
- [x] T004 `result_builder.py`: one walk per last tool; the radii once in the result.

## Phase 3 - Checks

- [x] T005 Spec 086's walker table gains the row.
- [x] T006 Size and time measured at base and head; ground-truth benchmark at base and head.
- [x] T007 ruff, ruff format, mypy strict on the touched modules; touched tests and
      `test_scanner_size.py` under `timeout -s KILL 120`.

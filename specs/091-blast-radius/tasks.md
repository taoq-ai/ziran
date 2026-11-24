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
- [x] T008 Review round: unhashable call names, a reached high-impact tool, the probe and prefix
      matches, `MAX_LISTED` pinned, one walk per last tool and one call match per build asserted
      structurally; spec 086 names the blast radius as the second reader of co-resident edges;
      trace-analysis chain dicts match the scan shape.

## Slice 2 (A-BLAST-RADIUS-REPORT)

- [x] T009 `tests/unit/application/test_blast_radius_report.py`: tags as given, none without tags,
      reachable and demonstrated tags apart, id over name, unreached, removed and holder nodes
      untagged, the config's external override, the loader's errors, the scan wiring and its
      warning, the Markdown and HTML sections (parts apart, external, tags, wording, escaping, one
      block per last tool, absent without radii) and the SARIF summary (counts, external from
      either part, sorted classes, no tools, attack results unchanged, a malformed radius).
- [x] T010 `DataTag`, `BlastRadiusConfig`, `BlastReach.tags`, `DetectorThresholds.blast_radius`.
- [x] T011 `blast_radius(tags=)`, `ResultBuilder` and `ziran scan` wiring.
- [x] T012 Markdown and HTML sections; SARIF properties.
- [x] T013 Docs; byte-identity against the base; mutation probes; ruff, ruff format, mypy strict;
      touched tests and `test_scanner_size.py` under `timeout -s KILL 120`.

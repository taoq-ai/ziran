# Tasks: stop on critical only from exploitation_setup onwards

Base: `origin/develop`. Branch `fix/stop-on-critical-late-phases`. Test first.

- [x] T001 Tests in `test_stop_on_critical_phases.py`, run red (8 failing).
- [x] T002 `STOP_ON_CRITICAL_PHASES` in `phase.py`.
- [x] T003 `_has_critical_finding` guard in `scanner.py` (749 of 750 lines).
- [x] T004 Touched tests and `test_scanner_size.py` green; ruff, format and strict mypy clean.
- [x] T005 Mutants: guard removed, guard inverted, EXECUTION dropped, RECONNAISSANCE added, default off. All killed.

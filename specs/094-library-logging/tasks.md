# Tasks: library logging stays off stdout

Base: `origin/develop` @ 2988b9a. Branch `fix/094-library-logging-stdout`. Test first.

- [x] T001 `tests/unit/test_logging_defaults.py`: six cases; four run red before T002.
- [x] T002 `logger.py`: `_route_to_stdlib_by_default()` at import.
- [x] T003 Run `test_logger.py`, `test_json_logging.py` and every test using `caplog` or
      `capture_logs`: all pass.
- [x] T004 Run `two_tier_judging.py compare --format markdown`: stdout holds only the table.
- [x] T005 Fix round 1 (quality): a fresh-interpreter test that logs before `setup_logging(log_format="json")` and reads structured `k == 1` (kills `cache_logger_on_first_use=True`); the stderr test checks the console renderer (kills a `JSONRenderer` swap); acceptance 5 as a subprocess test (every stdout line starts with `|`).

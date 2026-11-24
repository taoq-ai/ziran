# Feature Specification: library logging stays off stdout

**Feature Branch**: `fix/094-library-logging-stdout`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: G5-LIB-LOGGING (goal G-5).
**Base**: `develop` @ 2988b9a.

## The promise in our own words

Only the CLI calls `setup_logging`. Everywhere else (the Python API, the promptfoo provider, the
benchmark scripts) structlog runs unconfigured, and its default `PrintLogger` writes every event,
debug included, to stdout. `AttackLibrary()` prints `[info] attack_library_initialized`, and
`benchmarks/two_tier_judging.py compare --format markdown` mixes `[debug] prefilter_escalated`
lines into its table.

After this change, importing ziran routes its structlog events through stdlib logging when the
host has not configured structlog. Python's library convention follows: without a handler, INFO
and DEBUG stay silent, and WARNING and above reach stderr through stdlib's last-resort handler. A
host that configured stdlib logging receives ziran's events in its own handlers. A host that
configured structlog first keeps its setup. `setup_logging` and the CLI output do not change.

Outside: log content, the CLI formats, the web app's uvicorn logging.

## Acceptance scenarios

1. Fresh interpreter, no logging setup: `AttackLibrary()` leaves stdout empty.
2. Same interpreter: a ziran warning appears on stderr.
3. CLI path (`setup_logging` with json and text): the existing logging tests pass unchanged.
4. Tests that use `structlog.testing.capture_logs` still capture events.
5. `uv run python benchmarks/two_tier_judging.py compare --format markdown > out.md`: out.md
   holds only the table.

## Requirements

- **FR-001**: `get_logger` returns a logger that resolves on each call. While
  `structlog.is_configured()` is false it wraps `logging.getLogger(name)` with
  `filter_by_level`, the shared processors and a plain `ConsoleRenderer`; once structlog is
  configured it uses `structlog.stdlib.get_logger(name)`. Importing ziran never calls
  `structlog.configure`, so `is_configured()` stays false and a host's later configure (a
  processors-only call, or one guarded by `is_configured()`) behaves as it does without ziran.
- **FR-002**: `setup_logging` keeps its behaviour; once it runs, ziran's loggers follow its config.

## Assumptions

- The library default lives on ziran's own loggers, not in structlog's global config. Fix
  round 2 (arch) found that an import-time `structlog.configure` leaked into hosts: `configure`
  merges only the keys it is given, so a processors-only host call kept ziran's stdlib factory
  and dropped its info events, and an `is_configured()` guard skipped the host's setup.
  Overturned if a caller needs the concrete `BoundLogger` type from `get_logger` (an
  `isinstance` check); `git grep` over ziran/ and tests/ finds none.
- Resolving on each call has no cache, so a later `setup_logging` (the CLI imports modules
  before it configures logging) takes effect for every module-level logger. `filter_by_level`
  runs first, so a dropped debug event costs one level check and one wrap.

# Plan: library logging stays off stdout

`get_logger` in `ziran/infrastructure/logging/logger.py` returns `_LibraryLogger`, a proxy that
resolves on each attribute access. While structlog is unconfigured it wraps
`logging.getLogger(name)` with `filter_by_level`, the shared processors and
`ConsoleRenderer(colors=False, exception_formatter=plain_traceback)`; once configured it returns
`structlog.stdlib.get_logger(name)`. Global structlog config is never touched at import. Every
ziran module gets its logger from `get_logger`, so the default covers all of them. No new
dependency.

Tests: `tests/unit/test_logging_defaults.py` runs each case in a fresh interpreter, since
structlog's config is process-global: AttackLibrary stdout, silent info and debug, warning on
stderr, a host stdlib handler, a host structlog config kept, `capture_logs`. Fix round 2: import leaves
`is_configured()` false, a processors-only host configure after import, an `is_configured()`
guarded host configure, and `logger.exception` without structlog's `UserWarning`.

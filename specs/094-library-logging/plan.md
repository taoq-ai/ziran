# Plan: library logging stays off stdout

One function in `ziran/infrastructure/logging/logger.py`, `_route_to_stdlib_by_default`, runs at
import. When structlog is unconfigured it sets `structlog.stdlib.LoggerFactory`,
`structlog.stdlib.BoundLogger`, and the processors `filter_by_level`, the shared processors and
`ConsoleRenderer(colors=False)`. Every ziran module gets its logger from `get_logger` in this
module (no other module imports structlog), so the import always runs first. No new dependency.

Tests: `tests/unit/test_logging_defaults.py` runs each case in a fresh interpreter, since
structlog's config is process-global: AttackLibrary stdout, silent info and debug, warning on
stderr, a host stdlib handler, a host structlog config kept, `capture_logs`.

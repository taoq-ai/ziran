# Implementation Plan: Structured JSON logging via structlog

## Technical context
- Python 3.11+ (CI 3.11/3.12/3.13). New runtime dependency: `structlog` (issue #282 calls for it).
- Touches `ziran/infrastructure/logging/logger.py`, the CLI entry point, the scanner/phase/attack
  layers (context binding), and every `ziran/` logging call site (event migration).

## Design
1. **`ziran/infrastructure/logging/logger.py`** — rewrite `setup_logging` to configure structlog on
   top of stdlib logging (`structlog.stdlib.LoggerFactory` + `BoundLogger`). The processor chain
   merges contextvars, adds logger name, level, and an ISO-8601 UTC timestamp, then hands off to a
   `structlog.stdlib.ProcessorFormatter`. The final renderer is chosen by `log_format`:
   - `json` -> `structlog.processors.JSONRenderer` on a stderr `StreamHandler`.
   - `text` -> keep the existing `RichHandler` (no regression).
   `log_format` defaults to `None` -> resolve via `sys.stderr.isatty()` (text on TTY, json off).
   The formatter's `foreign_pre_chain` makes plain stdlib records render identically (FR-005). The
   `--log-file` handler is preserved. `get_logger` returns a structlog `BoundLogger`.
2. **Context binding** — reuse `structlog.contextvars`. Add thin helpers `bind_campaign`,
   `bind_phase`, `bind_vector`, and `clear_context` in the logging package so the scanner binds
   `campaign_id` once per campaign, the phase executor binds `phase` per phase, and the attack
   executor binds `vector_id` per attack. `merge_contextvars` in the chain pulls them into every
   line. No custom ContextVar plumbing beyond these one-line wrappers.
3. **Call-site migration** — convert `logger.x("msg %s", a)` to `logger.x("event_name", key=a)`
   across `ziran/`, file by file, suite green between commits. Files that only bind
   `logging.getLogger(__name__)` switch to `get_logger(__name__)` where they emit events.
4. **CLI** — add `--log-format` option to the root group; pass through to `setup_logging`.
5. **Docs** — `docs/reference/observability.md`: fields, flag, TTY behaviour, ingestion example.

## Phases
- P1: logger config (structlog + renderers + interop) + context helpers + unit tests.
- P2: CLI `--log-format` flag + auto-detect + integration test (json scan -> valid JSON lines).
- P3: mechanical call-site migration by file, suite green between commits.
- P4: docs + pyproject dependency.
- Gate: ruff, ruff format, mypy strict, pytest --cov >= 85%.

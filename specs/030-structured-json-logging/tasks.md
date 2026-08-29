# Tasks: Structured JSON logging via structlog

- [x] T001 Add `structlog` runtime dependency to `pyproject.toml` and lock (`uv add structlog`).
- [x] T002 Rewrite `setup_logging` in `ziran/infrastructure/logging/logger.py` to configure
      structlog over stdlib logging: contextvar merge + logger/level/ISO-UTC-timestamp processors,
      `ProcessorFormatter` with `foreign_pre_chain` for stdlib interop, renderer selected by
      `log_format` (`json` -> JSONRenderer on stderr StreamHandler; `text` -> RichHandler; `None` ->
      auto from `sys.stderr.isatty()`). Preserve `--log-file`. `get_logger` returns a structlog
      BoundLogger. Tests in `tests/unit/test_logger.py`: json line is valid JSON with
      `timestamp`/`level`/`logger`/`event`; text keeps RichHandler; auto-detect; stdlib interop.
- [x] T003 Add context helpers (`bind_campaign`, `bind_phase`, `bind_vector`, `clear_context`) in
      the logging package wrapping `structlog.contextvars`; unit test that a bound field appears in
      emitted JSON.
- [x] T004 Bind context in the scanner (`campaign_id`), phase executor (`phase`), and attack
      executor (`vector_id`); clear at campaign end. Test that phase/vector context flows into lines.
- [x] T005 Add `--log-format [json|text]` to the CLI root group
      (`ziran/interfaces/cli/main.py`); pass to `setup_logging`. Integration test: a scan with
      `--log-format json` emits only valid JSON lines with required fields on stderr.
- [x] T006 Migrate `ziran/` logging call sites to structured events (event name + kwargs); no
      `%`-formatted argument calls remain. File by file, suite green between commits.
- [x] T007 Add `docs/reference/observability.md` (fields, `--log-format`, TTY default, ingestion).
- [x] T008 Gates — ruff, ruff format, mypy strict, pytest --cov >= 85%; grep proves no `%`-format
      logging calls remain in `ziran/`.

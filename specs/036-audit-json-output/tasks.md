# Tasks: `ziran audit --format json`

Test-first: each implementation task is preceded by the failing test that it makes pass.
All code in `ziran/interfaces/cli/main.py` (`audit`), tests in
`tests/unit/test_cli_main.py` (`TestAuditCommand`). Parse `result.stdout`.

- [ ] T001 [US1] Failing test `test_audit_json_output_shape`: `.py` file with
      `api_key = "abcdefghijklmnop"`; `ziran audit FILE --format json`; assert stdout parses,
      top-level keys `files_analyzed == 1` and `findings`; finding keys exactly
      `{rule, severity, file, line, message}` with `rule == "SA001"`, `severity == "critical"`,
      `line == 1`; secret literal absent from stdout; exit 1. Run it, confirm it fails (exit 2,
      unknown option). (FR-001..FR-004, US1 scenarios 1-2)
- [ ] T002 [US2] Failing test `test_audit_json_exit_nonzero_at_severity`: file with only the
      `SA009` f-string `cur.execute(...)` line; `--format json --severity high` exits 1 with one
      finding; `--format json --severity critical` exits 0 with `findings == []`. Confirm it
      fails. (FR-005, FR-006, US2 scenarios 1 and 3)
- [ ] T003 [US2] Failing test `test_audit_json_clean_file`: `x = 1`; `--format json` exits 0,
      `findings == []`, `files_analyzed == 1`. Confirm it fails. (FR-006, US2 scenario 2)
- [ ] T004 [US1][US2] Implement: `@click.option("--format", "fmt",
      type=click.Choice(["text", "json"], case_sensitive=False), default="text", ...)` on
      `audit`, signature `audit(path, severity, fmt)`; after the severity filter, the JSON
      branch from plan.md Design step 2 (`click.echo(json.dumps(..., indent=2))`, then
      `sys.exit(1 if failed else 0)` with
      `failed = bool(report.findings) if severity else not report.passed`). Add a docstring
      example. Do not touch `_display_audit_report`. T001-T003 pass.
- [ ] T005 [US3] Regression: existing `test_audit_clean_file`, `test_audit_directory`,
      `test_audit_severity_filter` pass unmodified (FR-007).
- [ ] T006 Docs: `docs/reference/cli.md` `ziran audit` section: `--format` row, JSON example,
      exit-code table (0 / 1 / 2) and the note that text mode exits 1 only on critical. (FR-008)
- [ ] T007 Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). Revert any `uv.lock` drift before committing.
      Commit `feat(cli): add --format json to audit`; PR against `develop`.

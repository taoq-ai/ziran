# Implementation Plan: `ziran audit --format json`

**Branch**: `036-audit-json-output` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)

## Summary
Add a `--format text|json` option to the `audit` CLI command. JSON mode projects the existing
`AnalysisReport` into `{files_analyzed, findings: [{rule, severity, file, line, message}]}` on
stdout and exits 1 when findings at or above `--severity` remain (critical-only when no
`--severity`). Text mode and `_display_audit_report` are untouched. One function edited, three
tests added, one docs section extended.

## Technical Context
- Python 3.11+ (CI 3.11/3.12/3.13). Click 8.4 (`CliRunner.result.stdout` is stdout only).
- Dependencies: none new. `json` and `sys` are already imported at module level in
  `ziran/interfaces/cli/main.py` (lines 10-11).
- Logging goes to stderr (`ziran/infrastructure/logging/logger.py`), so stdout stays pure JSON.
- Data source: `ziran/application/static_analysis/analyzer.py` `AnalysisReport`
  (`files_analyzed`, `findings`, `passed`) and `StaticFinding` (`check_id`, `severity`,
  `file_path`, `line_number`, `message`, `context`, `recommendation`). No change to either.

## Constitution Check
| Principle | Status |
|-----------|--------|
| I. Hexagonal | Pass. Change is confined to the driving adapter (`interfaces/cli`); it reads the application-layer report, adds nothing to domain/application. |
| II. Type safety | Pass. New parameter annotated `fmt: str`; mypy strict. The dict built for `json.dumps` is an output serialisation at the CLI edge, not domain data, matching how `report --format json` serialises; no new Pydantic model needed. |
| III. Tests | Pass. Three `CliRunner` tests in the existing `TestAuditCommand` class of `tests/unit/test_cli_main.py`, following that file's conventions (it carries no per-test markers; add none). No network, no LLM. |
| IV. Async-first | N/A. Sync CLI entry point over the existing sync analyzer; no new I/O. |
| V. Extensibility | N/A. |
| VI. Simplicity | Pass. No new module, helper, model or dependency; `asdict` rejected because it would expose internal field names and the secret-bearing `context`. |

No violations; Complexity Tracking not needed.

## Design
All code changes are in **`ziran/interfaces/cli/main.py`, function `audit`** (around line 1070):

1. Add an option, following the sibling `report`/`poc` convention (`"--format", "fmt"`):
   ```python
   @click.option(
       "--format",
       "fmt",
       type=click.Choice(["text", "json"], case_sensitive=False),
       default="text",
       help="Output format (json: machine-readable findings on stdout).",
   )
   def audit(path: str, severity: str | None, fmt: str) -> None:
   ```
   Add a `ziran audit ./src --format json --severity high` line to the docstring examples.
2. After the existing severity filter and before `_display_audit_report(report)`:
   ```python
   if fmt == "json":
       click.echo(
           json.dumps(
               {
                   "files_analyzed": report.files_analyzed,
                   "findings": [
                       {
                           "rule": f.check_id,
                           "severity": f.severity,
                           "file": f.file_path,
                           "line": f.line_number,
                           "message": f.message,
                       }
                       for f in report.findings
                   ],
               },
               indent=2,
           )
       )
       failed = bool(report.findings) if severity else not report.passed
       sys.exit(1 if failed else 0)
   ```
   - Explicit keys (FR-003); `context`/`recommendation` deliberately omitted (FR-004).
   - `click.echo` (not the Rich `console`) so no markup/wrapping touches the JSON.
   - `sys.exit(0)` on success is explicit so the JSON branch never falls through to the text
     renderer.
   - Click `Choice(case_sensitive=False)` returns the canonical lowercase choice, so
     `fmt == "json"` holds for `--format JSON`.
3. `_display_audit_report` is not modified (FR-007).

**Tests** — `tests/unit/test_cli_main.py`, class `TestAuditCommand` (reuse the `runner` fixture
and `tmp_path`; parse `result.stdout`, not `result.output`, which also carries stderr):
- `test_audit_json_output_shape`: file `api_key = "abcdefghijklmnop"\n`; assert exit 1, keys
  `files_analyzed`/`findings`, finding keys exactly `{rule, severity, file, line, message}`,
  `rule == "SA001"`, `severity == "critical"`, `line == 1`, and `"abcdefghijklmnop"` not in
  stdout.
- `test_audit_json_exit_nonzero_at_severity`: file
  `def q(cur, x):\n    cur.execute(f"SELECT * FROM t WHERE id = {x}")\n` (only `SA009`, high);
  `--format json --severity high` exits 1 with one finding; `--severity critical` exits 0 with
  `findings == []`. (Verified against the default config on develop @ e8f451c.)
- `test_audit_json_clean_file`: `x = 1\n`; exit 0, `findings == []`, `files_analyzed == 1`.

**Docs** — `docs/reference/cli.md`, `ziran audit` section: add a `--format` row to the options
table, a short JSON example, and an exit-code table (0 clean, 1 findings at/above threshold or
critical without `--severity`, 2 usage error / path missing), with one sentence noting text mode
still exits 1 only on critical findings.

## Out of scope
- Changing text-mode exit semantics, `_display_audit_report`, `StaticAnalyzer`, or the
  silent-skip of unreadable files inside `analyze_file`.
- SARIF output, schema version field, `recommendation` in JSON (add on request).
- `update-agent-context.sh`: skipped; no new technology, and four parallel branches appending to
  `CLAUDE.md` would conflict (specs 029-032 did not update it either).

## Phases
- P1 (tests first): add the three failing tests; confirm they fail (`--format` unknown -> exit 2).
- P2: implement the option + JSON branch; tests pass; existing audit tests unchanged and green.
- P3: docs section.
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran`. Do not commit `uv.lock` drift.

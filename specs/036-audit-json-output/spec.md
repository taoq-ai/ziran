# Feature Specification: `ziran audit --format json`

**Feature Branch**: `036-audit-json-output`
**Created**: 2026-09-29
**Status**: Active
**Input**: WUWEI #33 (no ZIRAN issue). WUWEI's scanner gate shells out to `ziran audit <path>`,
which today prints only a Rich table. WUWEI needs machine-readable findings (rule, severity,
file, line, message) and a non-zero exit when findings at or above `--severity` remain. The
change is optional and must stay small: one CLI option on one command, no new module, no
change to text-mode behaviour.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Parse audit findings from a gate script (Priority: P1)
A CI gate (WUWEI) runs `ziran audit ./src --format json` and parses stdout as a single JSON
document listing every finding with its rule id, severity, file, line and message.

**Why this priority**: This is the whole feature; without parseable stdout the gate has to
scrape a Rich table.

**Independent Test**: Run `ziran audit <file-with-hard-coded-secret> --format json` through
`CliRunner`, `json.loads(result.stdout)`, and assert the top-level and per-finding keys.

**Acceptance Scenarios**:
1. **Given** a `.py` file containing `api_key = "abcdefghijklmnop"`, **When**
   `ziran audit FILE --format json` runs, **Then** stdout is one JSON object with
   `files_analyzed == 1` and a `findings` list whose entry has `rule == "SA001"`,
   `severity == "critical"`, `file` equal to the scanned path, `line == 1` and a non-empty
   `message`.
2. **Given** the same file, **When** the JSON is emitted, **Then** the secret literal
   (`abcdefghijklmnop`) does not appear anywhere in stdout (the finding's source-line
   `context` is not exported).

### User Story 2 — Gate on a severity threshold (Priority: P1)
The gate runs `ziran audit ./src --format json --severity high` and treats exit code 1 as
"findings at or above high remain" and exit code 0 as "clean at that threshold".

**Independent Test**: A file whose only finding is high severity (SQL injection, `SA009`)
exits 1 under `--format json --severity high`; a clean file exits 0.

**Acceptance Scenarios**:
1. **Given** a file whose only finding is `SA009` (high), **When**
   `ziran audit FILE --format json --severity high` runs, **Then** the exit code is 1 and the
   finding is in the JSON.
2. **Given** a clean file (`x = 1`), **When** `ziran audit FILE --format json` runs (with or
   without `--severity`), **Then** the exit code is 0 and `findings` is `[]`.
3. **Given** a file whose only finding is `SA009` (high), **When**
   `ziran audit FILE --format json --severity critical` runs, **Then** the exit code is 0 and
   `findings` is `[]` (the finding is below the threshold and filtered out).

### User Story 3 — Text mode unchanged (Priority: P1)
Existing users running `ziran audit PATH [--severity X]` without `--format` see exactly the
same output and exit codes as before.

**Independent Test**: The existing `TestAuditCommand` tests in `tests/unit/test_cli_main.py`
pass unmodified.

### Edge Cases
- `PATH` does not exist: Click rejects it (`click.Path(exists=True)`) with a usage error,
  exit code 2, before any output. Unchanged; this gives WUWEI a "could not run" code distinct
  from 1 ("findings").
- Unknown `--format` value: Click usage error, exit code 2.
- `--format JSON` (upper case): accepted (`case_sensitive=False`, same as `--severity`).
- Directory with no `.py` files: `{"files_analyzed": 0, "findings": []}`, exit 0.
- Finding without a line (file-level input-validation check, `line_number is None`):
  `"line": null`.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: `ziran audit` MUST accept `--format` with choices `text` and `json`
  (case-insensitive), default `text`.
- **FR-002**: With `--format json`, the command MUST write exactly one JSON object to stdout
  and nothing else on stdout: `{"files_analyzed": int, "findings": [...]}`. Logging already
  goes to stderr and is unaffected.
- **FR-003**: Each finding object MUST have exactly the keys `rule` (the `check_id`),
  `severity` (`critical|high|medium|low`), `file` (the analysed file path as a string),
  `line` (int or `null`) and `message`. These are the public contract names requested by
  WUWEI; the internal `StaticFinding` field names MUST NOT leak into the output.
- **FR-004**: The JSON MUST NOT include the finding's `context` (the matched source line) or
  `recommendation`. `context` can contain the secret that triggered SA001; excluding it keeps
  secret values out of gate logs.
- **FR-005**: The existing `--severity` filter MUST be applied before serialisation, so the
  JSON lists only findings at or above the threshold.
- **FR-006**: Exit codes in JSON mode:
  - with `--severity`: 1 if any finding at or above the threshold remains, else 0;
  - without `--severity`: 1 if any critical finding exists (same rule as text mode's
    `report.passed`), else 0;
  - 2: Click usage error (missing path, invalid option value), unchanged.
- **FR-007**: Text mode (default, or `--format text`) MUST be byte-for-byte unchanged in output
  and exit codes, and `_display_audit_report` MUST NOT be modified.
- **FR-008**: `docs/reference/cli.md` (the `ziran audit` section) MUST document `--format`,
  the JSON shape and the exit codes.

### Assumptions (recorded, most conservative reading)
- "Non-zero exit when findings exceed `--severity`" is read as "at or above", matching the
  existing `--severity` help text ("at this severity or above").
- Text mode keeps its current exit rule (1 only on critical, regardless of `--severity`). The
  threshold-based exit applies to JSON mode only, because the requirement forbids changing
  text-mode behaviour. The two modes therefore differ for `--severity high|medium|low`; this is
  documented in FR-008 docs.
- No schema version field: the object is small and WUWEI pins the ZIRAN version. Add one when
  the shape first changes incompatibly.

### Key Entities
- **Audit JSON document**: `files_analyzed` + `findings[]` of `{rule, severity, file, line,
  message}`; a projection of the existing `AnalysisReport` / `StaticFinding` dataclasses, no new
  model.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: `json.loads` succeeds on `result.stdout` for every `--format json` invocation in the
  tests, and the keys from FR-003 are present.
- **SC-002**: The three JSON-mode exit-code scenarios (US2 1-3) behave as specified.
- **SC-003**: Existing audit tests pass unmodified; no file outside `ziran/interfaces/cli/main.py`,
  `tests/unit/test_cli_main.py` and `docs/reference/cli.md` changes (plus this spec directory).
- **SC-004**: All gates pass: ruff, ruff format, mypy (strict), pytest coverage >= 85%.

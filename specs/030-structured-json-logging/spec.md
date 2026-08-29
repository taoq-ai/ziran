# Feature Specification: Structured JSON logging via structlog

**Feature Branch**: `030-structured-json-logging`
**Created**: 2026-08-29
**Status**: Active
**Input**: All logging uses plain `logging.getLogger()` producing unstructured text that is not
machine-queryable. Enterprise teams ingesting Ziran output into Elastic, Datadog, or Splunk need
structured JSON with stable fields. (GitHub issue #282.)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Machine-queryable JSON logs (Priority: P1)
An operator runs a scan in CI and pipes stderr to a log shipper. Every log line must be a single
valid JSON object carrying `timestamp`, `level`, `logger`, `event`, and, where the scanner has set
them, `campaign_id`, `phase`, and `vector_id`, plus any structured kwargs.

**Independent Test**: Run a scan with `--log-format json`; assert every non-empty stderr line
parses as JSON and carries the required base fields.

**Acceptance Scenarios**:
1. **Given** `--log-format json`, **When** a scan runs, **Then** every stderr log line is a JSON
   object with `timestamp`, `level`, `logger`, and `event`.
2. **Given** a running campaign, **When** a phase executes an attack, **Then** the emitted lines
   carry `campaign_id`, `phase`, and (for attack events) `vector_id`.

### User Story 2 — No regression in interactive Rich output (Priority: P1)
A developer runs a scan in a terminal. Output stays the human-readable Rich format it is today; the
default format is `text` on a TTY and `json` when stderr is not a TTY.

**Independent Test**: With no flag and a TTY stderr, the format resolves to `text` and the Rich
handler is installed; with a non-TTY stderr, it resolves to `json`.

**Acceptance Scenarios**:
1. **Given** no `--log-format` flag and a TTY, **When** logging is configured, **Then** Rich
   console output is used.
2. **Given** no flag and a non-TTY (piped) stderr, **When** logging is configured, **Then** JSON
   output is used.

### User Story 3 — Structured call sites (Priority: P2)
Log call sites in `ziran/` emit event names plus key/value kwargs instead of `%`-formatted
strings, so fields are queryable rather than embedded in prose.

**Independent Test**: A lint/grep check finds no `%`-formatted argument logging calls in `ziran/`.

## Requirements *(mandatory)*
- **FR-001**: `setup_logging` MUST configure structlog so log records render as either Rich text or
  JSON, selected by a `log_format` of `json`, `text`, or auto (TTY -> text, non-TTY -> json).
- **FR-002**: The CLI MUST expose `--log-format [json|text]` (default: auto-detect from stderr TTY).
- **FR-003**: JSON lines MUST carry `timestamp` (ISO-8601 UTC), `level`, `logger`, and `event`, and
  MUST merge context fields `campaign_id`, `phase`, `vector_id` when bound.
- **FR-004**: Context fields MUST be set via contextvars by the scanner/phase/attack layers and
  automatically merged into every log line emitted within that context, with no manual threading.
- **FR-005**: Plain `logging.getLogger()` call sites (third-party libraries and code added by other
  work) MUST keep working and MUST also render through the same JSON/text pipeline (stdlib interop).
- **FR-006**: `ziran/` logging call sites MUST be migrated to structured events (event name +
  kwargs); no `%`-formatted argument logging calls remain.
- **FR-007**: Existing Rich interactive output and the `--log-file` handler MUST NOT regress.
- **FR-008**: `structlog` MUST be added as a runtime dependency in `pyproject.toml`.
- **FR-009**: Documentation MUST be added at `docs/reference/observability.md`.

## Success Criteria *(mandatory)*
- **SC-001**: A scan with `--log-format json` emits only valid JSON lines on stderr, each with the
  required base fields; campaign/phase/vector context appears where bound.
- **SC-002**: Default (no flag) output is unchanged Rich text in a terminal and JSON when piped.
- **SC-003**: No `%`-formatted argument logging calls remain in `ziran/`.
- **SC-004**: All gates pass — ruff, ruff format, mypy strict, pytest coverage >= 85%.

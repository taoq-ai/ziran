# Feature Specification: watch-registry imports MCP servers from Claude Code configuration

**Feature Branch**: `035-watch-registry-claude-config`
**Created**: 2026-09-29
**Status**: Active
**Issue**: [#422](https://github.com/taoq-ai/ziran/issues/422) (part of #415; WUWEI #35 depends on it)
**Input**: `ziran watch-registry` watches MCP servers for drift, but only from a ZIRAN
`RegistryConfig` YAML whose `ServerEntry` has `name`, `url`, `transport`. Claude Code declares MCP
servers in a project `.mcp.json`, a plugin `.mcp.json`, and the `mcpServers` object of user
settings JSON, and most of them are stdio servers declared by `command` + `args`, which cannot be
expressed today. WUWEI (a Claude Code plugin) needs to baseline and watch exactly those servers,
and needs a stable exit-code contract to tell "drift found" from "could not run".

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Baseline and watch the servers a Claude Code config declares (Priority: P1)
A developer runs `ziran watch-registry --from-claude-config .mcp.json`. Every server in the file,
stdio or HTTP/SSE, is contacted, its `tools/list` is snapshotted as the baseline, and a later run
reports any tool-description change as drift.

**Why this priority**: This is the issue's acceptance criterion and what WUWEI #35 consumes.

**Independent Test**: Write a `.mcp.json` with one stdio server (an in-repo fixture MCP server run
with `sys.executable`) and one HTTP server (an httpx fake via `respx`, no network). Run the CLI
twice with the same snapshot dir, changing one tool description in between.

**Acceptance Scenarios**:
1. **Given** a `.mcp.json` with two servers (one stdio fixture, one HTTP fake), **When**
   `watch-registry --from-claude-config` runs the first time, **Then** both servers are registered
   and baselined (a snapshot file exists for each) and the command exits `0`.
2. **Given** that baseline, **When** a tool description changes on either server and the command
   runs again, **Then** the report contains a `description_changed` finding for that server and
   tool and the command exits `1`.
3. **Given** a plugin `.mcp.json` (servers either under `mcpServers` or as a flat top-level map)
   or a user settings JSON with a top-level `mcpServers` object, **When** loaded, **Then** the same
   servers are produced as for the equivalent project `.mcp.json`.

### User Story 2 — Secrets in the Claude Code config never leak (Priority: P1)
Claude Code configs routinely carry API keys in `env` and bearer tokens in `headers`. Running
`watch-registry` over such a config must never copy those values into snapshots, reports or logs.

**Why this priority**: Security requirement from the issue ("without copying secrets from env")
and the owner ("never copy `env` values or `headers` values"); a leak here is a vulnerability in a
security tool.

**Independent Test**: Put unique sentinel values in a stdio server's `env` and an HTTP server's
`headers`, run the CLI (baseline + drift run), then scan every file under the output directory and
the snapshot directory, plus captured stdout/stderr and logs, for the sentinels.

**Acceptance Scenarios**:
1. **Given** sentinel secret values in `env` and `headers`, **When** the command runs, **Then** no
   sentinel appears in any file under `--out` or `--snapshot-dir`, in CLI output, or in logs.
2. **Given** the same config, **When** servers are loaded, **Then** the key names (not values) of
   `env` and `headers` are recorded in the log for each server.
3. **Given** an HTTP server with `headers`, **When** it is fetched, **Then** the headers are sent
   on the request (values are used for the connection, only never persisted).

### User Story 3 — Poisoned tool metadata is flagged on first registration (Priority: P2)
The first time a server is registered there is no baseline to diff against, so a server that ships
already-poisoned tool descriptions would be silently baselined. `MCPMetadataAnalyzer` runs over
each server's `tools/list` on first registration and reports suspicious metadata.

**Independent Test**: `watch()` with an empty snapshot store and a fetcher returning a tool whose
description contains an exfiltration directive; assert a `tool_poisoning` finding; run again with
the baseline present and assert no `tool_poisoning` finding.

**Acceptance Scenarios**:
1. **Given** a server with no stored snapshot, **When** its `tools/list` contains a poisoned
   description, **Then** a finding with `drift_type="tool_poisoning"`, the analyzer's severity,
   the tool name, the field and the snippet is reported.
2. **Given** a server with a stored snapshot, **When** watched again, **Then** the analyzer is not
   run (drift diffing covers later changes).

### User Story 4 — Exit codes a wrapper can rely on (Priority: P1)
WUWEI maps exit `1` to "findings" and `2` to "could not run". `watch-registry` must keep "drift
found" distinct from "could not read config or reach a server", and document the codes.

**Acceptance Scenarios**:
1. **Given** neither or both of `--config` / `--from-claude-config`, **Then** exit `2` (usage).
2. **Given** a missing, non-JSON, or structurally invalid Claude config (no servers, an entry with
   neither `command` nor `url`, an unknown `type`), **Then** exit `2` with an error naming the file
   and server key only, and no report is written.
3. **Given** an unreadable or invalid `--config` YAML, **Then** exit `2` (today an uncaught
   exception gives `1`, indistinguishable from findings).
4. **Given** a server that cannot be launched, times out, or returns a protocol error, **Then**
   the other servers are still processed, the report is written, the unreachable server names are
   printed, its stored snapshot is untouched, and the command exits `2`.
5. **Given** a stdio server that never answers, **When** the fetch timeout elapses, **Then** the
   child process is killed and the server counts as unreachable.

### Edge Cases
- A stdio server writes non-JSON lines or JSON-RPC notifications to stdout before its response:
  skipped until the response with the matching `id` arrives.
- A large `tools/list` response (single line > 64 KiB): must be read without a stream-limit error.
- A stdio server writes diagnostics (possibly including its env) to stderr: stderr is discarded,
  never echoed.
- `${VAR}` / `${VAR:-default}` placeholders in `command`, `args`, `url`, `env`, `headers` are
  expanded from the environment (as Claude Code does); `${CLAUDE_PLUGIN_ROOT}` defaults to the
  config file's directory when unset. Unset placeholders without a default are left literal (the
  server then typically fails to start or authenticate, and is reported unreachable).
- `--from-claude-config` has no allowlist, exemptions or alerts: typosquat detection runs with an
  empty allowlist (yields nothing) and no alerts are sent.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: `watch-registry` MUST accept `--from-claude-config PATH`, mutually exclusive with
  `--config`; exactly one of the two is required (usage error, exit `2`, otherwise).
- **FR-002**: The Claude config loader MUST read: a project `.mcp.json` (`{"mcpServers": {...}}`),
  a plugin `.mcp.json` (`{"mcpServers": {...}}` or a flat `{name: server}` map), and user settings
  JSON (top-level `mcpServers` object). Each server key becomes `ServerEntry.name`.
- **FR-003**: Stdio servers (`command`, optional `args`, optional `type: "stdio"`) MUST map to a
  `ServerEntry` with `transport="stdio"`, `command`, `args`. HTTP servers (`url` with `type`
  `"http"` or absent) MUST map to `transport="streamable-http"`; `type: "sse"` to `transport="sse"`.
  Any other `type`, or an entry with neither `command` nor `url`, is a config error.
- **FR-004**: `ServerEntry` MUST gain optional `command: str | None` and `args: list[str]`; `url`
  becomes optional; a validator MUST require at least one of `url` / `command`. Existing YAML
  configs MUST keep validating unchanged.
- **FR-005**: The manifest fetcher MUST handle stdio servers by launching `command args...`,
  performing the MCP `initialize` handshake, sending `notifications/initialized`, and calling
  `tools/list` over newline-delimited JSON-RPC on stdin/stdout, bounded by a timeout (default
  30 s, same as the HTTP client); the child process MUST be terminated on success, error and
  timeout.
- **FR-006**: `env` and `headers` values MUST NOT appear in snapshots, reports, CLI output or
  logs. They MAY be used only to launch the stdio process (merged over the inherited environment)
  and as HTTP request headers. Only their key names are recorded (logged per server at load).
  The stdio child's stderr MUST be discarded. Error messages MUST name file, server key and field
  only, never values (pydantic errors rendered without input values).
- **FR-007**: A test MUST fail if a secret value from `env` or `headers` appears anywhere in the
  output directory (and the snapshot directory).
- **FR-008**: On first registration of a server (no stored snapshot), `MCPMetadataAnalyzer` MUST
  run over the server's `tools/list` and each finding MUST be reported as a `DriftFinding` with
  `drift_type="tool_poisoning"`, flowing through the existing report, alerting and exit-code paths.
- **FR-009**: `watch()` MUST surface which servers could not be fetched (not only log them), and
  MUST keep its existing guarantee that a failed fetch never overwrites a stored snapshot.
- **FR-010**: Exit codes (command-wide, both config modes), precedence `2` > `1` > `0`:
  `0` every server processed and no high/critical finding; `1` every server processed and at
  least one high/critical finding (drift, typosquat or tool poisoning); `2` could not run
  completely — usage error, unreadable/invalid config, at least one server unreachable (launch
  failure, timeout, protocol/HTTP error), or alert delivery failure.
- **FR-011**: The exit codes, the `--from-claude-config` input formats, the secret-handling rule
  and one example MUST be documented in `docs/reference/cli.md` (new `ziran watch-registry`
  section) and summarised in the command's `--help`.
- **FR-012**: Tests MUST use an in-repo fixture MCP stdio server and an httpx fake; no network or
  LLM calls. No new runtime dependencies (stdlib `asyncio` subprocess + existing `httpx`).

### Key Entities
- **ServerEntry** (domain): gains `command`, `args`, and secret-bearing `env` / `headers` held as
  `SecretStr`, excluded from serialisation and repr.
- **Claude MCP config**: external JSON document; parsed by an infrastructure loader into
  `list[ServerEntry]`.
- **DriftFinding** (domain): new `drift_type` value `tool_poisoning`.

## Assumptions (conservative readings, recorded instead of a clarify round)
- A1: The existing severity gate is kept: "drift found" = exit `1` only for high/critical findings
  (`description_changed`, `permission_changed`, typosquat, critical/high tool poisoning). Medium
  and low drift (`tool_added`, `tool_removed`, `schema_changed`) stay in the report with exit `0`.
  Changing the gate would alter behaviour for existing `--config` users beyond the issue's scope.
- A2: The exit-code contract is command-wide. The one behaviour change for `--config` users is
  that an unreachable server or unreadable config now exits `2` instead of `0` / `1`; a silent `0`
  for an unwatched server is a monitoring blind spot. The existing integration test that expects
  `0` for an unreachable server is updated accordingly.
- A3: `env` / `headers` values are needed to actually reach authenticated servers, so they are
  carried in memory as `SecretStr` (excluded from `model_dump`/`repr`) and used only for the
  connection. "Record only the key names" is satisfied by logging key names per server.
- A4: SSE and streamable-HTTP servers are fetched by the existing HTTP JSON-RPC fetcher exactly as
  `--config` entries with those transports are today; no new SSE wire protocol is implemented.
- A5: The stdio fetcher calls only `tools/list` (the issue's requirement and the only list used by
  drift diffing); `resources` / `prompts` are recorded empty for stdio servers.
- A6: The stdio child inherits ZIRAN's working directory (run from the project root, as Claude
  Code does).
- A7: With `--from-claude-config` there is no allowlist, exemption list, alert block or
  `snapshot_dir` override; `--snapshot-dir` applies.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: The two-server acceptance test (stdio fixture + HTTP fake) passes: baseline run
  exits `0` with two snapshots, drift run exits `1` with a `description_changed` finding.
- **SC-002**: The secret-leak test finds zero occurrences of the sentinel values in the output and
  snapshot directories, CLI output and logs.
- **SC-003**: Each exit code in FR-010 is asserted by at least one test.
- **SC-004**: All gates pass — ruff, ruff format, mypy (strict), pytest coverage >= 85%; no new
  runtime dependency in `pyproject.toml`.

# Feature Specification: Langfuse live trace pull

**Feature Branch**: `feat/074-langfuse-live-pull`
**Created**: 2026-11-18
**Status**: Draft
**Input**: plan item G2-LANGFUSE-LIVE (goal G-2), issue #287. Spec 011 shipped an API mode that
calls the v2-only SDK method `Langfuse().fetch_traces`, ignores `since` and `project_id`, has no
pagination, and pulls twice with `--alert`.

## The item in my words

`ziran analyze-traces --source langfuse` without `--input` pulls tool steps live from Langfuse
over its public REST API with `httpx` (a core dependency), not the SDK. It:

1. authenticates with HTTP basic auth from `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY`
   against `LANGFUSE_HOST` (default `https://cloud.langfuse.com`). A missing key exits 2 with a
   message that names both variables and never prints a key value;
2. sends the `--since` window (`24h`, `7d` or an ISO date) as the lower time bound, and the new
   `--session-id` as the session filter;
3. follows the API's pagination to the end;
4. waits for `Retry-After` on a 429, a bounded number of times, then exits 2 with a rate-limit
   message;
5. with `--incremental`, stores the newest pulled start time in
   `.ziran/trace_cache/langfuse-<12 hex of sha256(host and public key)>.json` and starts the next
   pull there. The file holds no key;
6. treats `TOOL` observations as tool calls, as well as `SPAN`, in file and API mode;
7. with `--alert`, pulls once for both the report and the alerts.

Outside: removing the `langfuse` extra or changing its bound (#479 owns `pyproject.toml`),
Langfuse write-back, OTel live pulls, a scheduler, a `--source langfuse-api` alias.

## User Scenarios & Testing

### User Story 1 - Pull and analyse live traces (Priority: P1)

An operator with Langfuse keys runs one command and gets the dangerous-chain report for the last
day of production traces, without exporting a file.

**Acceptance Scenarios**:

1. **Given** a mock Langfuse API holding 3 traces across 2 pages, **When**
   `analyze-traces --source langfuse --since 24h` runs with keys in env, **Then** all 3 are
   fetched with the lower time bound and basic auth sent, and the report lists their dangerous
   chains.
2. **Given** `--session-id s1`, **When** the pull runs, **Then** the request carries
   `sessionId=s1` and only that session's traces are analysed.
3. **Given** `LANGFUSE_SECRET_KEY` unset, **When** API mode runs, **Then** it exits 2 naming
   `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY`, and no key value appears in any output.
4. **Given** the mock answers 429 with `Retry-After: 1` once, **When** the pull runs, **Then** it
   waits and succeeds; **given** it keeps answering 429, **then** the command exits 2 with a
   rate-limit message.

### User Story 2 - Incremental pulls (Priority: P2)

A scheduled job runs the command every hour and analyses only what arrived since the last run.

1. **Given** `--incremental` and a first run that pulled up to T, **When** a second run starts
   after one new trace was added, **Then** it requests from T and analyses only the new trace,
   and the cache file holds no key.

### User Story 3 - One pull for report and alerts (Priority: P2)

1. **Given** `--alert --dry-run-alerts` in API mode, **When** the command runs, **Then** the mock
   sees one pull, not two.

### User Story 4 - TOOL observations (Priority: P3)

1. **Given** a trace whose tool steps are `TOOL` observations, **When** it is parsed in file or
   API mode, **Then** they become tool calls.

### Edge Cases

- `--since` malformed: exit 2 naming the accepted forms.
- A 4xx or 5xx other than 429: exit 2 with the status; the URL carries no key.
- A trace split across two pages: its observations join into one session.
- `--incremental` with no cache file: the pull starts at `--since`.
- Observations at exactly the stored start time that were already pulled are not analysed again.
- Alert delivery fails or the run errors: the cursor is not advanced, so the next run retries.
- `--incremental` with `--session-id`: refused with exit 2. The cursor is keyed on host and public
  key only, so a session-filtered pull would advance it past other sessions' traces.
- The API repeats a `meta.cursor` it already sent: the pull stops with exit 2 instead of looping.
- A JSON-string `input` nested deeply enough to raise `RecursionError`: the call keeps no
  arguments and the pull goes on.

## Requirements

- **FR-001**: API mode MUST use `httpx` on `GET /api/public/v2/observations` with basic auth.
- **FR-002**: `--since` MUST map to `fromStartTime`; `--session-id` to `sessionId`.
- **FR-003**: The pull MUST follow `meta.cursor` until it is absent.
- **FR-004**: A 429 MUST wait `Retry-After` seconds (capped) up to 3 retries, then fail.
- **FR-005**: Missing keys MUST fail before any request, naming both variables.
- **FR-006**: `--incremental` MUST persist only the start time and the observation ids at it.
- **FR-007**: `_parse_trace` MUST treat `SPAN` and `TOOL` as tool calls and decode a JSON-string
  `input` to arguments.
- **FR-008**: `--alert` MUST reuse the sessions from the analysis pull.
- **FR-009**: `--project-id`, when given, MUST drop observations of another project.

## Assumptions

- **REST over SDK**: httpx on the public API, because `fetch_traces` exists only in SDK v2 while
  the extra allows `<5` and dependabot #479 widens it to `<6`. Overturned if the owner wants the
  SDK.
- **Observations v2 instead of `/api/public/traces`**: the item names `GET /api/public/traces`
  paged with `page`, `fromTimestamp` and `GET /api/public/traces/{id}`. The Langfuse Cloud OpenAPI
  fetched on 2026-11-18 (`https://cloud.langfuse.com/generated/api/openapi.yml`) no longer lists
  either GET; it lists only `DELETE` on those paths, says new Cloud projects no longer populate
  the legacy trace tables, and names `GET /api/public/v2/observations` as the only real-time read
  path (other read endpoints lag about 10 minutes). So the pull uses that endpoint: one paged
  call with `fromStartTime`, `sessionId`, cursor pagination and `fields=core,basic,io`, grouped
  by `traceId` into the trace shape `_parse_trace` already reads. The acceptance intent (window,
  session filter, every page, basic auth) holds; the parameter names follow the current API.
  Overturned if the owner must support self-hosted Langfuse releases older than the v2
  observations API; then a fallback to the legacy trace endpoints is a follow-up.
- **Mock, not a recorded fixture**: no Langfuse keys are available to the builder, so the test
  fixture follows the documented `ObservationsV2Response` schema (`data`, `meta.cursor`; `input`
  as a raw string) rather than a recording from a live server. Overturned by a live recording
  that differs.
- **`--project-id` stays** and filters on the observation's `projectId` (API keys are already
  project-scoped). No `--source langfuse-api` alias. Overturned if the owner wants the issue's
  spelling.
- **Cursor granularity**: the cursor is the newest observation start time. A trace still running
  at pull time is analysed in parts across runs, so a chain that spans the boundary is missed.
  Overturned if users need whole-trace incremental pulls (then cursor on trace end time).
- **Agent name**: observations carry no trace-level `metadata.agent`, so API-mode sessions report
  agent `unknown`.

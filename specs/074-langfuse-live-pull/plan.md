# Implementation Plan: Langfuse live trace pull

**Branch**: `feat/074-langfuse-live-pull` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), `httpx` (core dependency) with `httpx.MockTransport`
in tests, stdlib `hashlib`/`json`/`os`/`re`/`asyncio`. No new dependencies; `pyproject.toml` is
untouched. API reference: Langfuse public API OpenAPI,
`https://cloud.langfuse.com/generated/api/openapi.yml`, `observations_getMany`
(`GET /api/public/v2/observations`) and `ObservationsV2Response`.

## Design

1. `LangfuseIngestor(transport=None)` (infrastructure adapter). `_ingest_api(since, session_id,
   project_id, incremental)`:
   - reads the keys and host from env; a missing key raises `ValueError` naming both variables;
   - parses `since` (`<n>h`, `<n>d` or ISO 8601) to a UTC datetime;
   - with `incremental`, loads `{"last_start_time", "ids_at_last"}` from the cache file; when
     present, the cursor replaces `since`;
   - pages `GET /api/public/v2/observations` with `fields=core,basic,io`, `limit=100`,
     `fromStartTime`, optional `sessionId`, and `cursor` until `meta.cursor` is absent;
   - a 429 sleeps `min(Retry-After, 60)` seconds up to 3 retries, then raises `RuntimeError`;
     other errors raise through `raise_for_status`;
   - drops observations already seen at the cursor time and of another `projectId`;
   - groups observations by `traceId` into `{"id", "sessionId", "observations"}` and parses each
     with `_parse_trace`;
   - keeps the new cursor on the instance; `save_cursor()` writes it atomically (temp file and
     `os.replace`). The CLI calls it only after the report and alerts succeed.
2. `_parse_trace`: tool types are `SPAN` and `TOOL`; a string `input` that decodes to a JSON
   object becomes the arguments.
3. `AnalyzerService`: `analyze_sessions(sessions)` and `emit_session_findings(sessions, ...)`
   hold the logic; `analyze` and `emit_findings` ingest and delegate, so their callers keep
   working.
4. CLI: new `--session-id` and `--incremental`; ingest once, analyse, write the report, alert
   from the same sessions, then save the cursor.
5. Docs: a live-API section in `docs/guides/analyze-traces.md`; example
   `examples/28-langfuse-live-analysis/`.

## Constitution check

Hexagonal: the HTTP client stays in the infrastructure adapter, the CLI wires it. Typed (mypy
strict). Async I/O with httpx. Tests first with markers. No new dependency.

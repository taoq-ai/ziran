# Phase 1 Data Model: Runtime Loop Alerting and Automation

All models are Pydantic v2 `BaseModel` (config/entities) or frozen dataclasses where noted. Severity reuses the existing `Severity = Literal["low", "medium", "high", "critical"]` from `ziran/domain/entities/attack.py`; ordering is `low(0) < medium(1) < high(2) < critical(3)`.

## Domain entities

### AlertableFinding (`ziran/domain/entities/alerting.py`, new)

The normalized unit every sink consumes. Both `DriftFinding` and trace `DangerousChain` matches convert to this.

| Field | Type | Notes |
|---|---|---|
| `fingerprint` | `str` | 16-char hex; stable dedup key (see R2). |
| `kind` | `Literal["registry_drift", "dangerous_chain"]` | Drives title prefix + formatting. |
| `severity` | `Severity` | Reused enum; compared against sink floor. |
| `title` | `str` | Human summary, e.g. `"Permission escalation on tool `write_file` (prod-mcp-server)"`. |
| `summary` | `str` | One-line text used for Slack `text` fallback. |
| `fields` | `dict[str, str]` | Ordered key→value detail pairs (server, tool, before/after, session, etc.). |
| `links` | `list[AlertLink]` | Labeled URLs (snapshot diff, trace source, matched finding, existing issue). |
| `remediation` | `str \| None` | Suggested fix (trace findings when a policy bundle covers the chain). |

**Validation**: `fingerprint` matches `^[0-9a-f]{16}$`; `fields` is insertion-ordered; `severity` must be a valid `Severity` literal.

**Fingerprint construction** (module helpers, pure functions):
- `drift_fingerprint(server, tool, drift_type) -> str`
- `trace_fingerprint(tool_chain_hash, session_id) -> str`
- `digest_fingerprint(chain_fingerprints) -> str` (derived only from the sorted set of chain fingerprints; no run date — so unchanged traces dedup across days)

### AlertLink (`alerting.py`, new)

| Field | Type | Notes |
|---|---|---|
| `label` | `str` | e.g. `"Snapshot diff"`, `"Trace (Langfuse)"`, `"Matched finding"`, `"Existing issue"`. |
| `url` | `str` | Absolute, remote-resolvable URL (http/https). Local filesystem paths MUST NOT be used. When no resolvable URL exists for the registry snapshot diff, omit the link and instead embed an inline before/after diff summary in `AlertableFinding.fields` (see FR-011). |

### DeliveryResult (`alerting.py`, new, frozen)

Returned by `AlertSink.emit` for one finding→one sink.

| Field | Type | Notes |
|---|---|---|
| `sink_name` | `str` | e.g. `"slack"`, `"github_issue"`. |
| `fingerprint` | `str` | Echoes the finding. |
| `status` | `Literal["sent", "deduped", "skipped_below_floor", "failed", "dry_run"]` | Outcome. |
| `detail` | `str \| None` | Issue URL on send/dedup, or error message on failure. |

### AlertOutcome (`alerting.py`, new)

Aggregate for a whole run; the CLI maps it to an exit code.

| Field | Type | Notes |
|---|---|---|
| `results` | `list[DeliveryResult]` | Flat list across all findings × sinks. |
| `any_failed` | `bool` (computed) | True if any `status == "failed"` → CLI exit 2. |
| `sent`, `deduped`, `failed` | `int` (computed) | Counts for the run summary. |

## Extended existing entity

### DriftFinding (`ziran/domain/entities/registry.py`, extend)

Existing fields unchanged (`server_name`, `drift_type`, `severity`, `tool_name`, `message`, `previous_value`, `current_value`, `suspected_canonical`). Add two methods:
- `fingerprint() -> str` → `drift_fingerprint(server_name, tool_name or "", drift_type)`.
- `to_alertable() -> AlertableFinding` → maps message/previous/current into `fields`, builds a snapshot-diff `AlertLink`.

> Domain note: `to_alertable` lives in the domain because it is pure mapping with no I/O, preserving the dependency rule.

## Application config models (`ziran/application/alerting/config.py`, new)

### AlertSinkConfig

| Field | Type | Default | Notes |
|---|---|---|---|
| `kind` | `Literal["slack", "github_issue"]` | — | Selects the adapter. |
| `severity_floor` | `Severity` | `"low"` | Per-sink minimum. |
| `webhook_url` | `str \| None` | None | Slack only; resolved via `!env`. |
| `repo` | `str \| None` | None | GitHub only, `owner/name`. |
| `labels` | `list[str]` | `[]` | GitHub only. |
| `token` | `str \| None` | None | GitHub only; resolved via `!env` or `GITHUB_TOKEN`. |
| `assignees` | `list[str]` | `[]` | GitHub only (optional). |

**Validation**: `kind == "slack"` requires `webhook_url`; `kind == "github_issue"` requires `repo` and a resolvable token. Secrets are populated from env (`!env`/`${VAR}`); a missing referenced var raises a clear config error before any network call.

### AlertConfig

| Field | Type | Notes |
|---|---|---|
| `alerts` | `list[AlertSinkConfig]` | The `alerts:` block parsed from registry/analyze config YAML. |

## Sink-internal model (GitHub)

### IssueMarker (encode/decode helpers in `github_issue_sink.py`)

Not a stored entity — a convention: the issue body ends with `\n\n<!-- ziran-fingerprint: {fp} -->`. `encode(body, fp)` appends it; the dedup search matches the literal `ziran-fingerprint: {fp}` substring across open + closed issues.

## State transitions

There is no persisted state machine. The only "state" is the existence of a GitHub issue carrying a fingerprint marker:

```
finding produced
   │
   ├─ severity < sink.floor ───────────────► skipped_below_floor
   │
   ├─ dry_run ─────────────────────────────► dry_run (payload printed, no I/O)
   │
   └─ search issues for marker
         ├─ found (open or closed) ────────► deduped (reuse existing URL)
         └─ not found ─► create/post
               ├─ 2xx ─────────────────────► sent
               └─ error / no creds ────────► failed (aggregated, non-blocking)
```

## Relationships

- `DriftFinding` →(`to_alertable`)→ `AlertableFinding` →(`emit`)→ `DeliveryResult` →(aggregate)→ `AlertOutcome`.
- Trace `DangerousChain` (observed_in_production) →(analyzer mapping)→ `AlertableFinding` (carries session/trace-source links, inherited severity, optional remediation from a matching `GuardrailPolicy`).
- `AlertConfig.alerts[*]` →(factory)→ concrete `AlertSink` instances (Slack/GitHub).

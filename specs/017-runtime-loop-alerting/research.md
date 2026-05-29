# Phase 0 Research: Runtime Loop Alerting and Automation

All `/speckit.clarify` questions were resolved in the spec's Clarifications section. The items below are the remaining design decisions that were deferred to planning (digest cadence, refresh-PR identity, Slack format) plus the technology choices introduced by this plan.

## R1 — Stateless GitHub-issue deduplication

**Decision**: Embed a hidden HTML-comment marker `<!-- ziran-fingerprint: <fp> -->` at the end of each created issue body. To dedup before creating, query the GitHub Search API: `GET /search/issues?q=repo:{owner}/{repo}+in:body+"ziran-fingerprint: {fp}"+is:issue` (no `is:open` qualifier, so closed issues match too). If any result is found, skip creation and reuse that issue's URL (also used to satisfy FR-014's "link to existing issue").

**Rationale**: Confirmed by clarify Q1 (Option A). Stateless, survives across machines/CI runners, and the same query gives both dedup and the existing-issue link. Avoids a local state file that could diverge.

**Alternatives considered**: Local `.ziran/alerts/state.json` map (rejected — state loss/divergence across runners); unique label per fingerprint (rejected — pollutes the label namespace, 50-label cap per issue).

**Caveats**: GitHub Search API is eventually consistent (seconds) and rate-limited (30 req/min authenticated). At the expected volume (tens of findings/run) this is fine; if a future high-volume need arises, batch the search. Marker must be a stable, collision-resistant string (see R3).

## R2 — Fingerprint composition

**Decision**:
- Drift finding fingerprint = `sha256("drift|" + server_name + "|" + tool_name + "|" + drift_type)[:16]` (clarify Q2, Option A — excludes `current_value`).
- Trace finding fingerprint = `sha256("trace|" + tool_chain_hash + "|" + session_id)[:16]` (FR-016). `tool_chain_hash` is the ordered tool-name sequence of the `DangerousChain`.

**Rationale**: Matches clarify decisions. A short hex digest is human-skimmable in the marker and stable across runs. The `drift|`/`trace|` prefix prevents cross-type collisions.

**Alternatives considered**: Including changed value in drift fp (rejected per Q2 — noisy); raw concatenation without hashing (rejected — leaks long values into markers and search queries).

## R3 — Partial-delivery exit-code contract

**Decision**: Define an exit-code convention for the alerting-capable commands:
- `0` — success (all eligible findings delivered, or nothing eligible).
- `2` — partial delivery failure (detection succeeded, ≥1 sink delivery failed).
- `1` — fatal/usage error (config invalid, unhandled exception), consistent with existing CLI behavior.

The dispatcher returns an aggregated `AlertOutcome` (per-sink success/failure); the CLI maps "any delivery failed" → exit 2.

**Rationale**: Clarify Q3 (Option A). Distinct code lets schedulers alert on delivery problems without conflating them with crashes. Note: existing `watch-registry` already uses `SystemExit(1)` to signal "critical/high findings present"; that severity-gate exit is orthogonal and preserved — delivery-failure (2) is evaluated only when the run otherwise completes. Documented precedence: fatal(1) > delivery-failure(2) > severity-gate(existing) > 0.

**Alternatives considered**: single generic non-zero (rejected — Q3 B); always exit 0 (rejected — Q3 C, masks failures).

## R4 — `!env VAR_NAME` YAML tag

**Decision**: Register a custom PyYAML constructor for the `!env` tag on a dedicated SafeLoader subclass in `infrastructure/config/env_yaml.py`: `!env SLACK_WEBHOOK_URL` resolves to `os.environ["SLACK_WEBHOOK_URL"]` at load time, raising a clear error if the var is unset. Also accept plain `${VAR}` interpolation for parity with the existing `browser_adapter.py` convention.

**Rationale**: No `!env` tag exists yet (confirmed in exploration). A scoped loader keeps the tag out of the global `yaml.safe_load` used elsewhere. Resolving at load time keeps secrets out of committed config (FR-005, SC-006).

**Alternatives considered**: Pydantic `SecretStr` + manual env lookup in each model (rejected — repetitive, doesn't support inline `!env` in arbitrary fields); environment-variable-only with no YAML tag (rejected — spec explicitly calls for `!env VAR_NAME`).

## R5 — Slack message format

**Decision**: Post Slack Block Kit JSON (a `blocks` array: a header block with severity emoji + finding kind, a section with fields for server/tool/before-after or tool-sequence/session, and a context block linking the snapshot diff or trace). Fall back to a `text` summary field for notification previews.

**Rationale**: Block Kit renders structured, scannable alerts and is the Slack-recommended webhook payload. The `text` fallback guarantees a useful mobile/notification preview.

**Alternatives considered**: Plain `text` only (rejected — poor scannability for multi-field findings).

## R6 — GitHub issue creation transport

**Decision**: The runtime **issue sink** calls the GitHub REST API directly via `httpx.AsyncClient` (`POST /repos/{owner}/{repo}/issues`, `GET /search/issues`) with a bearer token from env. The **policy-refresh composite Action** (#273) instead shells out to the `gh` CLI for scan/export/PR operations.

**Rationale**: The sink runs inside async ZIRAN flows where httpx is the established convention and respx makes request-shape testing clean. The Action runs on a GitHub runner where `gh` is pre-installed and idiomatic for PR creation; using it keeps the Action dependency-free (#273 "no new runtime deps").

**Alternatives considered**: shelling `gh` from the sink (rejected — not async, harder to unit-test, adds a CLI dependency to the library path); using a REST client inside the Action (rejected — reinvents `gh`).

## R7 — Trace digest mode

**Decision**: `AnalyzerService.emit_findings(sinks, digest=False)`. When `digest=True`, group all dangerous-chain matches from the run into one aggregated GitHub issue (table of chains, sessions, severities) with a digest-level fingerprint = `sha256("trace-digest|" + "|".join(sorted(chain_fingerprints)))[:16]`. The run date is deliberately excluded so re-running on unchanged traces (even on a later day) reuses the same digest issue rather than filing a duplicate (SC-002). If the set of chains changes, the fingerprint changes and a new digest issue is opened — the desired signal that the production picture changed. When `False` (default), emit one finding per `(chain, session)`.

**Rationale**: Per the spec's "digest window = analyzer run" assumption, kept consistent with SC-002's sequential no-duplicate guarantee. Keeps dedup uniform (digest issue also carries a marker).

**Alternatives considered**: time-windowed scheduler (rejected — out of scope per Assumptions); per-session always (rejected — high-traffic agents flood issues).

## R8 — Single long-lived refresh PR

**Decision**: The Action commits regenerated policies to a fixed branch `ziran/policy-refresh` and uses `gh pr create` if no open PR for that branch exists, else `gh pr edit`/push to update it. The branch acts as the stable identity, so squash vs merge-commit strategy on the base branch doesn't spawn duplicates (FR-024).

**Rationale**: A fixed head branch is the simplest stable PR identity and is how `peter-evans/create-pull-request` and similar patterns achieve idempotent refresh PRs.

**Alternatives considered**: PR title/label search to locate the PR (rejected — fragile vs renamed titles); new branch per run (rejected — spawns duplicate PRs, violates FR-024).

## R9 — respx for sink integration tests

**Decision**: Add `respx` as a dev dependency; integration tests register routes for the Slack webhook URL and GitHub REST/search endpoints, then assert the recorded request method/URL/headers/JSON body and simulate dedup by returning a search hit on the second call.

**Rationale**: httpx-native, no real server, precise request-shape assertions (spec acceptance). Lighter than pytest-httpserver.

**Alternatives considered**: pytest-httpserver (rejected — heavier, spins a real WSGI server); `unittest.mock` on the client (rejected — doesn't verify real serialization/request shape, which the acceptance criteria require).

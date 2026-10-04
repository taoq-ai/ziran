# Feature Specification: configurable delay between HTTP discovery probes

**Feature Branch**: `051-probe-rate-limiting`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #73 (release 0.42.0, "faster scans, truer graphs" batch).
**Base**: `develop` @ cff8b7f (release 0.41.0).
**Siblings (parallel, separate worktrees)**: #288 / spec 049 (scan cache), #393 / spec 050
(LangGraph-native scanning), #368 / spec 052 (web route-handler tests). No shared file: this
feature touches `ziran/domain/entities/target.py`, `ziran/infrastructure/adapters/http_adapter.py`
(`_probe_discover` only), their unit tests and two docs pages.
**Scope**: black-box probe discovery in `HttpAgentAdapter` (protocols REST, OpenAI, MCP, A2A,
AUTO). Lightweight spec: one validated config field and one `asyncio.sleep` between probes.
**Input**: `HttpAgentAdapter._probe_discover()` sends the three `_DISCOVERY_PROBES` back to back
with no pause. Remote agents behind IP-based rate limiting can answer the second and third probe
with `429`, and `_probe_discover` silently drops those probes (`except ProtocolError: continue`),
so discovery returns fewer capabilities than the agent exposes. The issue asks for a configurable
delay between probe requests (e.g. 0.5-1 s), configurable via `TargetConfig`.

## User Scenarios & Testing *(mandatory)*

Shared fixtures for the scenarios below (all offline):
- **Stub handler**: an `AsyncMock` assigned to `adapter._handler` whose `send` returns
  `{"content": "- search_files: searches files\n"}` (or raises `ProtocolError`), exactly as
  `tests/unit/test_http_adapter.py::TestProbeDiscoverExtended` does today.
- **Patched sleep**: `asyncio.sleep` patched with an `AsyncMock` for the duration of the call, so
  no test actually waits and every requested delay is observable.

### User Story 1 - Probes are paced by a configurable delay (Priority: P1)

An operator scans a rate-limited remote agent. Discovery waits a fixed delay between consecutive
probe requests so the agent does not see a burst; the operator can tune the delay in the target
YAML.

**Why this priority**: the issue's whole ask.

**Independent Test**: `HttpAgentAdapter(TargetConfig(url=..., probe_delay=d))` with the stub
handler and patched sleep; call `_probe_discover()`.

**Acceptance Scenarios**:
1. **Given** `probe_delay=1.5` and three probes, **When** `_probe_discover()` runs, **Then**
   `asyncio.sleep` is awaited exactly `len(_DISCOVERY_PROBES) - 1` (= 2) times, each with `1.5`.
2. **Given** the same setup with a shared call log, **Then** the order of events is
   `send, sleep, send, sleep, send`: no sleep before the first probe and none after the last.
3. **Given** a `TargetConfig` without `probe_delay`, **Then** the delay used is the default
   `0.5` seconds (2 sleeps of `0.5`).
4. **Given** every probe raises `ProtocolError`, **Then** the result is `[]` (unchanged) and the
   probes are still paced (2 sleeps): a failed request still reached the remote endpoint.
5. **Given** a YAML target file with `probe_delay: 2`, **When** `load_target_config` loads it,
   **Then** `config.probe_delay == 2.0`.

### User Story 2 - A zero delay disables pacing (Priority: P1)

An operator scanning a local or unthrottled agent sets `probe_delay: 0` to get today's
back-to-back behaviour and the fastest discovery.

**Why this priority**: issue/brief criterion "delay 0 must skip sleeping"; keeps the old
behaviour available.

**Independent Test**: as US1 with `probe_delay=0`.

**Acceptance Scenarios**:
1. **Given** `probe_delay=0`, **When** `_probe_discover()` runs, **Then** `asyncio.sleep` is never
   awaited and all three probes are sent.

### User Story 3 - Invalid delays are rejected at load time (Priority: P2)

**Why this priority**: the target YAML is operator input (a trust boundary); a negative or absurd
delay must fail fast with the existing config error, not hang or crash mid-scan.

**Acceptance Scenarios**:
1. **Given** `TargetConfig(url=..., probe_delay=-0.1)` or `probe_delay=30.01`, **Then**
   `pydantic.ValidationError` is raised; `probe_delay=0` and `probe_delay=30` are accepted.
2. **Given** a YAML target file with `probe_delay: -1`, **When** `load_target_config` loads it,
   **Then** `TargetConfigError` is raised (the loader already wraps `ValueError`, which
   `ValidationError` subclasses).

### Edge Cases
- A single probe or an empty probe list would mean zero sleeps (the rule is "between probes");
  `_DISCOVERY_PROBES` is a fixed 3-element module constant, so this is not separately tested.
- The structured discovery request (`handler.discover()`) that precedes the probes and the
  protocol auto-detection requests are not paced; only the probe loop is (issue scope).
- Probes still bypass `_send_with_retry`: a `429` on a probe is dropped as today, not retried
  with `Retry-After`. The delay lowers the chance of hitting the limit; it does not recover a
  throttled probe. Recorded as a follow-up below.
- Attack traffic (`invoke`) is not paced by this field; it already goes through
  `_send_with_retry` (retries, `Retry-After`, circuit breaker).
- `BrowserAgentAdapter` is out of scope: its interactions are already paced by
  `BrowserConfig.settle_delay`, and it does not use `_probe_discover`.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (config field)**: `TargetConfig` gains `probe_delay: float`, default `0.5`, validated
  `ge=0`, `le=30`, with a `description`. It is a top-level target key in YAML (sibling of
  `timeout`), not nested under `retry`.
- **FR-002 (pacing)**: `HttpAgentAdapter._probe_discover()` awaits
  `asyncio.sleep(self._config.probe_delay)` before every probe except the first, and only when
  `probe_delay > 0`. There is no sleep before the first probe or after the last one.
- **FR-003 (error path unchanged)**: a probe that raises `ProtocolError` is still skipped
  (`continue`); it still counts as a sent probe for pacing, so the next probe is still delayed.
  The returned capabilities (ids, names, types, dedup) are unchanged for identical responses.
- **FR-004 (validation)**: out-of-range values raise `ValidationError` from `TargetConfig` and
  `TargetConfigError` from `load_target_config`.
- **FR-005 (docs)**: `docs/guides/remote-agents.md` and `docs/concepts/remote-scanning.md` each
  gain one `probe_delay` line in their retry/timeout YAML example; `remote-agents.md` also states
  in one sentence that discovery now waits 0.5 s between probes by default (about 1 s added per
  discovery run) and that `probe_delay: 0` restores the previous back-to-back behaviour.
- **FR-006 (no regressions)**: existing tests pass unmodified, including
  `TestProbeDiscoverExtended` and `TestHttpAdapterStreamAndDiscover`; no new dependency; no change
  to `_send_with_retry`, `invoke`, the circuit breaker, or `BrowserAgentAdapter`; `uv.lock`
  unchanged.

### Assumptions (recorded, most conservative reading)
- **Field location**: `TargetConfig`, not `RetryConfig`. The issue names `TargetConfig`;
  `RetryConfig` governs what happens after a failure (attempts, backoff, retryable codes), while
  the probe delay paces requests on the success path. A top-level key next to `timeout` keeps the
  YAML honest (`retry.probe_delay` would suggest it only applies on retries).
- **Default 0.5 s, not 0**: the issue says "e.g. 0.5-1s"; the low end protects rate-limited
  targets with the smallest slowdown (2 gaps = +1.0 s per discovery). This is a behaviour change
  for existing users; it is documented (FR-005) and `0` opts out.
- **Upper bound 30 s**: matches `RetryConfig.backoff_factor` (`le=30.0`); a larger value is far
  more likely a typo (ms vs s) than intent.
- **Delay only, no retry routing**: routing probes through `_send_with_retry` would honour `429`
  + `Retry-After` and the circuit breaker, but a throttled probe could then cost up to
  `max_retries` backoffs (default 3; `Retry-After` capped at 120 s each), probe failures would
  feed the circuit breaker shared with the attack phase, and `CircuitOpenError` would need
  handling in the probe loop. The issue does not ask for retries, so this is a follow-up.
- No jitter, no token bucket, no per-target rate limiter: a fixed delay is what the issue asks
  for (`ziran/application/rate_limiting/AsyncTokenBucket` wraps LLM clients only).

### Follow-ups (not in this feature; no issue created)
- Route probes through `_send_with_retry` (keep `except ProtocolError: continue`, also catch
  `CircuitOpenError`) so a `429` on a probe honours `Retry-After` instead of being dropped.
- Per-target pacing of attack traffic (a general request rate limiter for `invoke`).

### Key Entities
- **TargetConfig.probe_delay** (`float`, seconds, `0 <= x <= 30`, default `0.5`).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US3 pass as unit tests with a stub handler and a patched `asyncio.sleep` (no
  network, no real waiting, no keys).
- **SC-002**: the ordering test proves "between probes only" (`send, sleep, send, sleep, send`)
  and the zero test proves no sleep at `probe_delay=0`.
- **SC-003**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-004 (unverified offline)**: that 0.5 s actually avoids a given real agent's rate limit
  cannot be shown without a live rate-limited endpoint; not claimed. The PR says so.

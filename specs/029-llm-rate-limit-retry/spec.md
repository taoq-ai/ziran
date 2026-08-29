# Feature Specification: Rate-limiting and retry with exponential backoff on LLM provider calls

**Feature Branch**: `029-llm-rate-limit-retry`
**Created**: 2026-08-29
**Status**: Active
**Input**: GitHub issue #281 — "feat(runtime): rate-limiting + retry with exponential backoff on LLM provider calls". The scanner defaults to `max_concurrent_attacks=5`; beyond that, provider 429s cascade as attack failures because there is no client-side rate-limiting or retry loop. Long campaigns against rate-limited targets are fragile, and ZIRAN cannot distinguish "the agent refused" from "the provider throttled us".

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Transient throttling does not lose work (Priority: P1)

A security analyst runs a campaign whose AI-powered features call an LLM provider. The provider intermittently returns HTTP 429 (rate limited) and transient 5xx errors under load. Every such call must eventually succeed after client-side retry, so no attack is dropped merely because the provider throttled the request.

**Why this priority**: This is the reported defect. Dropped calls are recorded as attack failures, corrupting the campaign result and wasting the whole run.

**Independent Test**: Drive a wrapped client against a mock provider that returns 429 for the first N attempts of each call and then succeeds; assert every call returns a successful response and none surface as an error.

**Acceptance Scenarios**:

1. **Given** a provider that returns 429 on the first two attempts and then succeeds, **When** a call is made through the rate-limited client with `max_retries >= 2`, **Then** the call returns the successful response and no error is raised.
2. **Given** a provider that returns a transient 5xx (500/502/503/504) then succeeds, **When** a call is made, **Then** the call is retried and returns successfully.
3. **Given** a provider that returns 429 on every attempt, **When** retries are exhausted, **Then** the client raises `LLMError` (the call genuinely failed) rather than silently returning empty content.

---

### User Story 2 - Concurrency does not cascade into provider errors (Priority: P1)

The same analyst raises concurrency to 20+ parallel attacks. A client-side token-bucket limiter paces outbound calls to stay under the configured requests-per-minute and tokens-per-minute, so a burst of concurrent calls does not trip the provider's server-side limit in the first place.

**Why this priority**: Retry alone treats the symptom; the limiter prevents the burst. Together they make high-concurrency campaigns viable, which is the headline capability.

**Independent Test**: Fire 20 concurrent calls through the limiter configured to a low RPM against a mock provider that returns 429 whenever it receives more than the allowed rate; assert all 20 complete successfully.

**Acceptance Scenarios**:

1. **Given** a rate-limited client configured with `rpm=60`, **When** 20 calls are issued concurrently, **Then** all 20 complete successfully and the observed outbound rate does not exceed the configured limit.
2. **Given** `rpm=0` (disabled), **When** calls are issued, **Then** the limiter imposes no delay (opt-out preserved).

---

### User Story 3 - Logs distinguish throttling from refusal (Priority: P2)

Reviewing the run, the analyst must be able to tell a throttled-and-retried call apart from an attack that actually failed. Throttle/retry events are logged distinctly; only genuine post-retry failures are reported as attack failures.

**Why this priority**: Without this distinction, throttling noise is misread as vulnerability signal (or its absence), undermining trust in the report.

**Independent Test**: Trigger a retried call and an exhausted-retries call; assert a throttle warning is logged for the retry with the status code and attempt count, and that only the exhausted call raises `LLMError`.

**Acceptance Scenarios**:

1. **Given** a call that is throttled once then succeeds, **When** it completes, **Then** a WARNING log records "provider throttled" with the provider, status code, attempt number, and backoff delay, and no error is surfaced.
2. **Given** a call whose retries are exhausted, **When** it fails, **Then** the raised `LLMError` message states the call failed after N retries, so downstream logging attributes it to the provider, not the agent.

---

### Edge Cases

- Provider returns a `Retry-After` header on a 429: the backoff MUST honor it instead of the computed delay when it is larger.
- A non-retryable error (e.g. 400 bad request, 401 auth): MUST fail immediately without consuming retries.
- Tokens-per-minute limit with unknown completion length: prompt tokens are estimated before the call (completion length is not known in advance); the estimate paces the bucket, it is not billed exactly.
- `rpm`/`tpm` set to `0`: the corresponding bucket is disabled (no pacing).
- Streaming calls (`stream_complete`): rate-limiting applies to acquiring the slot before the stream opens; retry does not apply to streaming at all (see Assumptions).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: All outbound LLM provider calls created through the LLM client factory MUST route through a shared rate-limiting + retry wrapper, so the behavior is provider-agnostic (fixed once at the shared layer, not per adapter).
- **FR-002**: The wrapper MUST enforce a client-side token-bucket limiter for requests-per-minute (`rpm`) and tokens-per-minute (`tpm`) before each provider call.
- **FR-003**: The wrapper MUST retry calls that fail with a retryable error (HTTP 429 and transient 5xx: 500, 502, 503, 504) up to a configurable `max_retries`, using exponential backoff with jitter between attempts.
- **FR-004**: Backoff MUST honor a provider-supplied `Retry-After` value when present and larger than the computed delay.
- **FR-005**: Non-retryable errors (e.g. 400, 401, 403, 404) MUST fail immediately without consuming retry budget.
- **FR-006**: When retries are exhausted, the wrapper MUST raise `LLMError` whose message states the number of retries attempted, so the failure is attributable to the provider.
- **FR-007**: Rate-limit and retry parameters (`rpm`, `tpm`, `max_retries`) MUST be configurable per campaign via CLI flags and environment variables, with sensible per-provider defaults.
- **FR-008**: Throttle/retry events MUST be logged at WARNING via the existing logging API, recording provider, status code, attempt number, and delay — distinct from attack-failure logging.
- **FR-009**: Setting `rpm=0` or `tpm=0` MUST disable the corresponding limiter (opt-out), and the wrapper MUST be transparent (same `BaseLLMClient` interface) so no caller changes are required.
- **FR-010**: An integration test with a mock provider returning 429s at a known rate MUST demonstrate that no call is lost and that concurrency of 20 completes end to end.

### Key Entities

- **RateLimitConfig**: Pydantic model holding `rpm`, `tpm`, `max_retries`, base backoff delay, and max backoff cap; exposes per-provider defaults.
- **Token bucket**: An async primitive that admits requests/tokens at a fixed refill rate and makes callers wait when the bucket is empty.
- **RateLimitedClient**: A `BaseLLMClient` decorator wrapping an inner client; applies the buckets to `complete()` and `stream_complete()`, and the retry loop to `complete()` only.
- **Retry classification**: The rule deciding whether a raised exception is retryable (status code / error type).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Against a mock provider that returns 429s at a known rate, a batch of concurrent calls (concurrency 20) completes with zero lost calls.
- **SC-002**: A call throttled up to `max_retries` times succeeds; a call throttled beyond `max_retries` raises `LLMError` naming the retry count.
- **SC-003**: With a configured `rpm`, the observed outbound call rate does not exceed the limit under concurrent load.
- **SC-004**: Logs separate "provider throttled, retried N times" (WARNING) from genuine attack failure, verifiable in tests.
- **SC-005**: `docs/reference/runtime-config.md` documents the rate-limiting flags, env vars, and per-provider defaults.
- **SC-006**: All quality gates pass: lint, format, type-check (mypy strict), and test suite with coverage >= 85%. No new runtime dependencies.

## Assumptions

- The "LLM provider calls" in scope are ZIRAN's own outbound calls made through `create_llm_client` (the internal LLM backbone: LLM-judge, adaptive strategies, pentest agent). Target-agent adapters (`BaseAgentAdapter` implementations) are a separate driving path and are out of scope; wrapping them would be a per-adapter change, which contradicts the shared-layer directive.
- Token accounting for `tpm` uses a character-based estimate for prompt tokens (chars/4), consistent with the existing many-shot token heuristic. Exact tokenization (tiktoken) is out of scope — it would add a dependency for marginal pacing accuracy.
- `stream_complete` is rate-limited (the slot is acquired before the stream opens) but not retried, neither before nor after the first chunk: cleanly replaying a partially consumed async generator is out of scope, and the internal LLM backbone (judge, adaptive strategies) uses `complete()`, not streaming. Deferred and marked with a `ponytail:` note in the wrapper.
- The existing stdlib `logging` API is used for throttle logs; logging infrastructure is owned by a parallel change and is not restructured here.

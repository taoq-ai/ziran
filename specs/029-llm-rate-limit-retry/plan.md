# Implementation Plan: Rate-limiting and retry with exponential backoff on LLM provider calls

**Branch**: `029-llm-rate-limit-retry` | **Date**: 2026-08-29 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/029-llm-rate-limit-retry/spec.md`

## Summary

Wrap every LLM client produced by `create_llm_client` in a transparent
`RateLimitedClient` decorator that (1) paces outbound calls through async
token buckets for requests-per-minute and tokens-per-minute, and (2) retries
retryable provider errors (HTTP 429 and transient 5xx) with exponential
backoff plus jitter, up to a configurable `max_retries`. Pure logic (token
bucket, retry classification, config with per-provider defaults) lives in
`ziran/application/rate_limiting/`; the `BaseLLMClient` decorator lives beside
the other LLM clients in `ziran/infrastructure/llm/`. CLI flags and env vars
feed a `RateLimitConfig`. Verified by unit tests (bucket pacing, retry
classification, backoff) and an integration test with a mock 429 provider at
concurrency 20.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (config model), `asyncio` + `random` + `time` (stdlib) for the bucket and backoff, existing `BaseLLMClient` / `create_llm_client`, Click (CLI). No new runtime dependencies.
**Storage**: N/A — configuration only (in-memory Pydantic model from CLI/env).
**Testing**: pytest (`@pytest.mark.unit`, `@pytest.mark.integration`), `asyncio_mode=auto`; new `tests/unit/test_rate_limiting.py`, `tests/integration/test_rate_limited_client.py`.
**Target Platform**: Linux/macOS CLI + library.
**Project Type**: Single project (hexagonal: domain / application / infrastructure / interfaces).
**Performance Goals**: Limiter adds bounded async waits only when over rate; retry adds backoff waits only on failure. No measurable overhead on the happy path.
**Constraints**: mypy strict, ruff clean, line length 100, coverage >= 85%.
**Scale/Scope**: One new application submodule (3 small files), one new infrastructure client, factory + CLI wiring, docs, and tests.

## Constitution Check

*GATE: Must pass before Phase 0. Re-check after design.*

- **I. Hexagonal Architecture** — PASS. Pure limiter/retry/config logic sits in `application/rate_limiting/` (depends only on stdlib + Pydantic). The decorator implements the existing infrastructure port `BaseLLMClient` and lives in `infrastructure/llm/`, wired at the `create_llm_client` factory (interfaces call the factory, not the wrapper directly). Dependencies flow inward.
- **II. Type Safety** — PASS. `RateLimitConfig` is a Pydantic model; all functions fully annotated; mypy strict must pass.
- **III. Test Coverage** — PASS. Unit tests for bucket, retry classification, backoff, config defaults; integration test for the 429/concurrency scenario. Coverage >= 85%.
- **IV. Async-First** — PASS. The bucket and retry loop are async; no blocking sleeps (`asyncio.sleep`). Reuses httpx-style transient handling conceptually but needs no sync I/O.
- **V. Extensibility via Adapters** — PASS. The wrapper is a decorator over `BaseLLMClient`; adding it changes no adapter and keeps the interface. New behavior is opt-out via `rpm=0`/`tpm=0`.
- **VI. Simplicity** — PASS. Reuses the existing char/4 token heuristic and stdlib primitives; no new dependency; decorator + one small submodule, no speculative abstraction.

No violations → Complexity Tracking not required.

## Decisions (ADR-style, resolved from code + issue)

1. **Scope = internal LLM backbone, not target adapters.** The issue text conflates target-provider 429s with ZIRAN's own LLM calls, but the brief directs a shared-layer fix at "the existing LLM client path" (`BaseLLMClient` / `create_llm_client`). Target-agent adapters are a distinct driving path; wrapping them would be per-adapter, contradicting the directive. Decision: wrap only the `create_llm_client` factory output. Recorded so a future ticket can extend to adapters if needed.
2. **Placement split.** Token bucket, retry classification, and `RateLimitConfig` are pure logic → `application/rate_limiting/`. The `BaseLLMClient` decorator is an infrastructure adapter → `infrastructure/llm/rate_limited_client.py`. Keeps the constitution's dependency direction intact while honoring the issue's requested `rate_limiting/` location for the reusable core.
3. **TPM estimation = chars/4 heuristic.** Completion length is unknown before the call; exact tokenization would add `tiktoken`. Decision: acquire `ceil(prompt_chars / 4)` tokens from the tpm bucket before the call. Lazy, dependency-free; marked with a `ponytail:` comment naming the ceiling (swap for tiktoken if pacing accuracy ever matters).
4. **Retry classification by duck-typed status code.** `LLMError` wraps the provider exception as `__cause__`; litellm is an optional dep, so we do not import it. Decision: classify retryable when the exception or its `__cause__` exposes `status_code` in {429, 500, 502, 503, 504}, or the type name contains `RateLimit`/`Timeout`/`APIConnection`/`ServiceUnavailable`/`InternalServer`. Everything else is non-retryable.
5. **Backoff = exponential + full jitter, honoring Retry-After.** `delay = min(cap, base * 2**attempt)`, then `random.uniform(0, delay)` (full jitter, avoids thundering herd under concurrency 20). If the exception carries a `retry_after` / `Retry-After` value larger than the computed delay, use it. `asyncio.sleep` between attempts.
6. **Per-provider defaults.** `RateLimitConfig.for_provider(name)` returns defaults: OpenAI `rpm=10000`, Anthropic `rpm=4000`, default `rpm=60`; `tpm=0` (disabled) by default; `max_retries=3`, `base_delay=0.5s`, `max_delay=30s`. CLI/env override individual fields.
7. **Single lock per bucket.** The bucket uses one `asyncio.Lock` — correct for a single campaign event loop at concurrency 20. Marked with a `ponytail:` comment (per-shard buckets only if a future multi-loop use appears).

## Project Structure

### Documentation (this feature)

```text
specs/029-llm-rate-limit-retry/
├── plan.md              # This file
├── spec.md              # Feature spec
└── tasks.md             # Work breakdown
```

### Source Code (repository root)

```text
ziran/application/rate_limiting/
├── __init__.py          # Exports RateLimitConfig, AsyncTokenBucket, is_retryable, backoff_delay
├── config.py            # RateLimitConfig (Pydantic) + per-provider defaults
├── token_bucket.py      # AsyncTokenBucket async primitive (rpm/tpm pacing)
└── retry.py             # is_retryable(exc) + backoff_delay(attempt, cfg) + retry_after(exc)

ziran/infrastructure/llm/
├── rate_limited_client.py   # RateLimitedClient(BaseLLMClient) decorator (buckets + retry loop + throttle logs)
└── factory.py               # CHANGE create_llm_client / _from_env to wrap the inner client

ziran/interfaces/cli/main.py # ADD --llm-rpm / --llm-tpm / --llm-max-retries flags (env: ZIRAN_LLM_RPM/_TPM/_MAX_RETRIES); thread into create_llm_client

docs/reference/runtime-config.md  # NEW rate-limiting section (flags, env, per-provider defaults)
mkdocs.yml                        # ADD nav entry for runtime-config.md

tests/
├── unit/test_rate_limiting.py            # bucket pacing, retry classification, backoff, config defaults, wrapper retry/log
└── integration/test_rate_limited_client.py  # mock 429 provider, no-loss + concurrency-20 end to end
```

**Structure Decision**: Single-project hexagonal layout (existing). Reusable
logic in the application layer; the `BaseLLMClient` decorator in infrastructure
beside the other LLM clients; wiring at the factory and CLI (interfaces).

## Complexity Tracking

No constitution violations — section intentionally empty.

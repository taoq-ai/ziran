# Tasks: Rate-limiting and retry with exponential backoff on LLM provider calls

**Input**: Design documents from `/specs/029-llm-rate-limit-retry/`
**Prerequisites**: plan.md, spec.md

**Tests**: Included — TDD per the common charter (one failing test first, then minimum code to green).

**Branch**: `029-llm-rate-limit-retry` (off `develop`)

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 / US2 / US3 from spec.md

## Path Conventions

Single-project hexagonal layout: source in `ziran/`, tests in `tests/`.

---

## Phase 1: Setup

- [ ] T001 Confirm branch `029-llm-rate-limit-retry` is checked out off `develop`; create the empty package `ziran/application/rate_limiting/__init__.py`.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The pure primitives every user story depends on.

- [ ] T002 [P] Write failing unit tests in `tests/unit/test_rate_limiting.py` for `RateLimitConfig`: default values, `for_provider("openai"/"anthropic"/"unknown")` defaults, and field validation (non-negative). Then implement `ziran/application/rate_limiting/config.py` to green.
- [ ] T003 [P] Write failing unit tests for `is_retryable(exc)`, `retry_after(exc)`, and `backoff_delay(attempt, cfg)` in `tests/unit/test_rate_limiting.py`: 429/5xx retryable, 400/401 not, `status_code` on `__cause__` detected, type-name fallback, backoff monotonic within jitter cap, Retry-After honored when larger. Then implement `ziran/application/rate_limiting/retry.py` to green.
- [ ] T004 Write failing unit tests for `AsyncTokenBucket`: `rpm=0` never waits, a low-rpm bucket makes the 2nd immediate acquire wait, refill admits after elapsed time. Then implement `ziran/application/rate_limiting/token_bucket.py` (single `asyncio.Lock`, monotonic clock) to green.
- [ ] T005 Populate `ziran/application/rate_limiting/__init__.py` exports (`RateLimitConfig`, `AsyncTokenBucket`, `is_retryable`, `retry_after`, `backoff_delay`).

**Checkpoint**: Reusable rate-limit core exists and is unit-green.

---

## Phase 3: User Story 1 - Transient throttling does not lose work (P1) 🎯 MVP

**Goal**: A wrapped client retries retryable errors and only fails after exhausting retries.

**Independent Test**: Mock inner client raises a 429 `LLMError` for the first N attempts then succeeds → call returns the success; raises every time → `LLMError` after `max_retries`.

- [ ] T006 [US1] Write failing unit tests in `tests/unit/test_rate_limiting.py` for `RateLimitedClient.complete`: (a) inner raises retryable then succeeds → returns response; (b) inner raises non-retryable → raises immediately, no extra attempts; (c) inner always retryable → raises `LLMError` after exactly `max_retries` retries, message names the count.
- [ ] T007 [US1] Implement `ziran/infrastructure/llm/rate_limited_client.py`: `RateLimitedClient(BaseLLMClient)` wrapping an inner `BaseLLMClient` + `RateLimitConfig`; `complete()` acquires rpm+tpm slots, calls inner, catches `LLMError`, retries per `is_retryable` with `backoff_delay`/`retry_after` and `asyncio.sleep`; `health_check` delegates; `stream_complete` acquires slot then delegates. Make T006 green.

**Checkpoint**: US1 verifiable and green.

---

## Phase 4: User Story 3 - Logs distinguish throttling from refusal (P2)

**Goal**: Throttle/retry logged at WARNING with status + attempt + delay; exhaustion raises `LLMError`.

**Independent Test**: caplog on a retried call shows a "provider throttled" WARNING; exhausted call raises `LLMError` naming retries.

- [ ] T008 [US3] Write failing unit test using `caplog` asserting a WARNING is logged on retry with provider, status code, attempt number, and delay; assert no log on the happy path. Add the `logger.warning(...)` call in `rate_limited_client.py` to green (existing stdlib `logging` API).

**Checkpoint**: Throttle logging distinct from attack-failure path.

---

## Phase 5: User Story 2 - Concurrency does not cascade (P1)

**Goal**: Token-bucket pacing keeps 20 concurrent calls under the provider limit; no call lost.

**Independent Test**: 20 concurrent calls through a low-rpm limiter against a mock provider that 429s above its rate → all succeed.

- [ ] T009 [US2] Write failing integration test `tests/integration/test_rate_limited_client.py` (`@pytest.mark.integration`): mock `BaseLLMClient` that raises a 429 `LLMError` when its concurrent-call rate exceeds a threshold (or on first K attempts per call); wrap in `RateLimitedClient` with `rpm` set low and `max_retries` sufficient; `asyncio.gather` 20 concurrent `complete()` calls; assert all 20 return successfully (no loss) and the mock never saw an over-limit burst succeed.
- [ ] T010 [US2] Adjust `RateLimitedClient` / bucket if the concurrency test surfaces a pacing bug; keep unit tests green.

**Checkpoint**: SC-001/SC-003 demonstrated end to end.

---

## Phase 6: Wiring (factory + CLI + env)

- [ ] T011 Write failing unit tests for factory wiring: `create_llm_client(...)` returns a `RateLimitedClient` wrapping the inner client; `create_llm_client_from_env` reads `ZIRAN_LLM_RPM`/`_TPM`/`_MAX_RETRIES`. Then update `ziran/infrastructure/llm/factory.py` to build a `RateLimitConfig` (from explicit args, else `for_provider`) and wrap the inner client. Make green.
- [ ] T012 Add `--llm-rpm` / `--llm-tpm` / `--llm-max-retries` Click options (env: `ZIRAN_LLM_RPM` / `ZIRAN_LLM_TPM` / `ZIRAN_LLM_MAX_RETRIES`) to the `scan` command in `ziran/interfaces/cli/main.py`; thread them into the `create_llm_client(...)` call. Mirror onto the pentest command's `create_llm_client` call.

---

## Phase 7: Docs & Quality Gates

- [ ] T013 Create `docs/reference/runtime-config.md` with a rate-limiting section: the three flags, their env vars, per-provider defaults, backoff behavior, and the "throttled vs failed" logging distinction. Add a nav entry in `mkdocs.yml`.
- [ ] T014 Run all quality gates from the worktree root: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (coverage >= 85%). Fix any failures.

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002–T005)** → user stories.
- **US1 (T006–T007)** depends on T002–T005. **US3 (T008)** depends on T007. **US2 (T009–T010)** depends on T007 (and benefits from T004).
- **Wiring (T011–T012)** depends on T007. **Docs/Gates (T013–T014)** last.
- TDD: every implementation task is preceded by its failing test in the same task.

## Parallel Opportunities

- T002 and T003 are independent (config vs retry helpers, same test file — coordinate edits or sequence).
- Docs (T013) can be drafted in parallel with wiring once the flag names are fixed.

## MVP Scope

US1 (T001–T007) is the minimum shippable increment: retry-with-backoff so no call is lost to transient throttling. US2 (pacing at concurrency 20) and US3 (log distinction) complete the issue's acceptance criteria.

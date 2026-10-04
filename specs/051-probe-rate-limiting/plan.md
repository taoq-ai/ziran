# Implementation Plan: configurable delay between HTTP discovery probes

**Branch**: `051-probe-rate-limiting` | **Date**: 2026-10-04 | **Spec**: [spec.md](spec.md)
**Issue**: #73 (release 0.42.0) | **Base**: `develop` @ cff8b7f
**Parallel siblings**: #288 / spec 049, #393 / spec 050, #368 / spec 052. None of them edits
`ziran/domain/entities/target.py` or `HttpAgentAdapter._probe_discover`; #393 adds a new adapter
module, not this one. No shared-file coordination needed.

## Summary
Add one validated field, `TargetConfig.probe_delay` (seconds, default `0.5`, `0..30`), and in
`HttpAgentAdapter._probe_discover()` await `asyncio.sleep(probe_delay)` before every probe except
the first, skipping the call entirely when the delay is `0`. Nothing else in the adapter changes:
probes keep calling `self._handler.send()` directly and keep `except ProtocolError: continue`.
Docs gain one YAML line in two pages plus a one-sentence note about the new default.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (`Field` validation), stdlib `asyncio`. No new dependencies.
**Storage**: N/A (target YAML is read by the existing `load_target_config`).
**Testing**: pytest, `@pytest.mark.unit`; `AsyncMock` handler assigned to `adapter._handler` (the
`TestProbeDiscoverExtended` pattern in `tests/unit/test_http_adapter.py`);
`unittest.mock.patch("ziran.infrastructure.adapters.http_adapter.asyncio.sleep",
new_callable=AsyncMock)` so no test waits; `tmp_path` YAML files (the `TestLoadTargetConfig`
pattern in `tests/unit/test_target_config.py`). No network, no LLM, no keys.
**Target Platform**: `HttpAgentAdapter` (`ziran scan --target`, `ziran discover --target`, the
promptfoo provider and the factories, all of which build it from `TargetConfig`).
**Project Type**: single Python package.
**Performance Goals**: default adds `2 * 0.5 = 1.0 s` per `discover_capabilities()` call;
`probe_delay: 0` adds nothing.
**Constraints**: mypy strict; line length 100; `_send_with_retry`, `invoke`, the circuit breaker
and `BrowserAgentAdapter` untouched. `http_adapter.py` is 606 lines, `target.py` 456; neither has
a size guard.

## Design decision: `TargetConfig` vs `RetryConfig`
`TargetConfig`. (1) The issue names `TargetConfig`. (2) `RetryConfig` fields
(`max_retries`, `backoff_factor`, `retry_on`) all describe what happens after a failed request;
the probe delay applies to every probe, successful or not, so `retry.probe_delay` would mislead.
(3) A top-level key sits next to `timeout` under the existing `# Resilience` comment block, the
other always-on request knob. Bound `le=30` mirrors `RetryConfig.backoff_factor`.

## Design decision: delay only, no `_send_with_retry` routing
Conservative choice per the release brief and the issue text (which asks only for a delay).
Routing probes through `_send_with_retry` would (a) honour `429` + `Retry-After`, but (b) let one
throttled probe cost up to `max_retries` (default 3) waits of up to 120 s each, (c) count probe
failures against the circuit breaker the attack phase relies on, and (d) require catching
`CircuitOpenError` in the probe loop. Recorded as a follow-up in spec.md; not built.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | The field lives on the domain entity `TargetConfig` (pydantic only, no outer imports). The sleep lives in the infrastructure adapter that already owns the probe loop and already imports `asyncio`. No application or interface change. |
| II. Type safety | PASS | `probe_delay: float` is a validated Pydantic `Field` (`ge=0`, `le=30`); no new untyped code. |
| III. Tests | PASS | Test-first: unit tests for the field (default, bounds, YAML load, YAML rejection) and for the pacing (count, value, order, zero, error path). Existing tests unmodified. |
| IV. Async-first | PASS | `await asyncio.sleep(...)`, non-blocking. |
| V. Extensibility | PASS | No port change; `BaseAgentAdapter` untouched. |
| VI. Simplicity | PASS | One field, one guarded `await`. No rate-limiter class, no jitter, no retry rewiring, no CLI flag. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #73 implementer. Names, defaults, bounds and the YAML key MUST NOT change without
updating this file.

### 1. `ziran/domain/entities/target.py` - `TargetConfig`

Insert directly after `timeout` in the `# Resilience` block:

```python
    probe_delay: float = Field(
        default=0.5,
        ge=0,
        le=30,
        description="Delay in seconds between discovery probe requests (0 disables)",
    )
```

- YAML key: top-level `probe_delay` (e.g. `probe_delay: 1.0`). Not under `retry:`.
- `TargetConfig(url=..., probe_delay=-0.1)` and `probe_delay=30.01` raise
  `pydantic.ValidationError`; `load_target_config` turns that into `TargetConfigError` through
  its existing `except (ValueError, TypeError, KeyError)` (no loader change).
- No other model changes. `RetryConfig` is not touched.

### 2. `ziran/infrastructure/adapters/http_adapter.py` - `HttpAgentAdapter._probe_discover`

Signature unchanged: `async def _probe_discover(self) -> list[AgentCapability]`. The loop becomes:

```python
        delay = self._config.probe_delay
        for index, probe in enumerate(_DISCOVERY_PROBES):
            if index and delay:
                await asyncio.sleep(delay)
            try:
                result = await self._handler.send(probe)
                ...  # unchanged parsing
            except ProtocolError:
                continue
```

- Sleep is outside the `try`, before probes 2..n only; a failed previous probe still delays the
  next one (the request reached the endpoint).
- `delay == 0` -> `asyncio.sleep` is never called.
- `_DISCOVERY_PROBES`, parsing, dedup, return value and `discover_capabilities()` unchanged.
- Docstring gains one line: probes are spaced by `TargetConfig.probe_delay` seconds.

### 3. Docs

- `docs/guides/remote-agents.md`, `## Retry & Timeout` YAML block, after `timeout: 30`:
  `probe_delay: 0.5    # Seconds between discovery probes (0 disables)`; plus one sentence below
  the block: discovery waits `probe_delay` seconds between its three probe requests to avoid
  tripping rate limits; the 0.5 s default adds about 1 s per discovery run compared with earlier
  releases, and `probe_delay: 0` restores back-to-back probes.
- `docs/concepts/remote-scanning.md`, YAML example, after `timeout: 30`:
  `probe_delay: 0.5    # Seconds between discovery probes (0 disables)`.

No CLI flag, no `scanner_config` key, no output-shape change, no metadata key.

## How each acceptance criterion is proven offline

| Criterion | Proof (all unit, no network, no real waiting) |
|---|---|
| US1.1 n-1 sleeps with configured value | `probe_delay=1.5`, patched `asyncio.sleep` (`AsyncMock`); assert `sleep.await_count == len(_DISCOVERY_PROBES) - 1` and every `await_args_list` entry is `call(1.5)`; `handler.send.await_count == len(_DISCOVERY_PROBES)`. |
| US1.2 between probes only | One `events: list[str]`; `handler.send.side_effect` appends `"send"` and returns the stub content; sleep mock `side_effect` appends `"sleep"`; assert `events == ["send", "sleep", "send", "sleep", "send"]`. |
| US1.3 default 0.5 | `TargetConfig(url=...).probe_delay == 0.5`; adapter built without the field -> sleeps awaited with `0.5`. |
| US1.4 errors still paced, result unchanged | `handler.send.side_effect = ProtocolError("fail")`; result `[]`, `sleep.await_count == 2`. |
| US1.5 YAML load | `tmp_path` YAML with `url` + `probe_delay: 2` -> `load_target_config(...).probe_delay == 2.0`. |
| US2.1 zero disables | `probe_delay=0`; `sleep.assert_not_awaited()`; `handler.send.await_count == 3`. |
| US3.1 bounds | `ValidationError` for `-0.1` and `30.01`; `0` and `30` accepted. |
| US3.2 YAML rejection | `tmp_path` YAML with `probe_delay: -1` -> `pytest.raises(TargetConfigError)`. |
| FR-006 no regressions | Existing `TestProbeDiscoverExtended` and `TestHttpAdapterStreamAndDiscover` pass unmodified (they now really sleep 2 x 0.5 s each; accepted, as the existing `_send_with_retry` tests already really sleep). Full gate run. |
| SC-004 real rate limits | Unverified offline; stated in the PR. |

## Project Structure

### Documentation (this feature)
```text
specs/051-probe-rate-limiting/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (files touched)
```text
ziran/domain/entities/target.py                 # + TargetConfig.probe_delay
ziran/infrastructure/adapters/http_adapter.py   # _probe_discover: enumerate + guarded sleep
tests/unit/test_target_config.py                # + TestProbeDelayConfig
tests/unit/test_http_adapter.py                 # + TestProbeDelay
docs/guides/remote-agents.md                    # + 1 YAML line, 1 sentence
docs/concepts/remote-scanning.md                # + 1 YAML line
```

## Complexity Tracking
None.

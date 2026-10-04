# Tasks: configurable delay between HTTP discovery probes

Base: `origin/develop` @ cff8b7f. Work on branch `051-probe-rate-limiting`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys, no real waiting in new tests
(patch `ziran.infrastructure.adapters.http_adapter.asyncio.sleep` with `AsyncMock`). New test
classes carry `@pytest.mark.unit`. The field name, default, bounds and YAML key are exactly those
in [plan.md §Public contract](plan.md#public-contract). Existing tests MUST NOT be modified.

## Phase 1 - Config field (FR-001, FR-004; US1.3, US1.5, US3)

- [x] T001 [P] Failing tests in `tests/unit/test_target_config.py`, new class
      `TestProbeDelayConfig` (`@pytest.mark.unit`):
      - default: `TargetConfig(url="https://x.com").probe_delay == 0.5`;
      - bounds: `probe_delay=0` and `probe_delay=30` accepted; `-0.1` and `30.01` raise
        `ValidationError`;
      - YAML load: `tmp_path / "target.yaml"` with `url: https://x.com` and `probe_delay: 2` ->
        `load_target_config(path).probe_delay == 2.0`;
      - YAML rejection: same with `probe_delay: -1` -> `pytest.raises(TargetConfigError)`.
      Run `uv run pytest tests/unit/test_target_config.py -k ProbeDelay` and confirm failures.
- [x] T002 Add `TargetConfig.probe_delay` in `ziran/domain/entities/target.py` exactly per plan §1
      (after `timeout`). T001 passes.

## Phase 2 - Pacing in `_probe_discover` (FR-002, FR-003; US1.1, US1.2, US1.4, US2)

- [x] T003 Failing tests in `tests/unit/test_http_adapter.py`, new class `TestProbeDelay`
      (`@pytest.mark.unit`), placed after `TestProbeDiscoverExtended`; each builds
      `HttpAgentAdapter(TargetConfig(url="https://x.com", probe_delay=...))`, assigns an
      `AsyncMock` handler to `adapter._handler`, and patches sleep with `AsyncMock`:
      - `test_sleeps_between_probes_only`: `probe_delay=1.5`; `sleep.await_count ==
        len(_DISCOVERY_PROBES) - 1`; every awaited call is `call(1.5)`;
        `handler.send.await_count == len(_DISCOVERY_PROBES)`;
      - `test_sleep_order`: shared `events` list fed by `handler.send.side_effect` (append
        `"send"`, return `{"content": "- search_files: searches files\n"}`) and the sleep mock's
        `side_effect` (append `"sleep"`); assert `events == ["send", "sleep", "send", "sleep",
        "send"]`;
      - `test_default_delay`: config without `probe_delay`; all sleeps awaited with `0.5`;
      - `test_zero_delay_never_sleeps`: `probe_delay=0`; `sleep.assert_not_awaited()`; three sends;
      - `test_failed_probes_still_paced`: `handler.send.side_effect = ProtocolError("fail")`;
        result `== []`; `sleep.await_count == 2`.
      Import `_DISCOVERY_PROBES` from `ziran.infrastructure.adapters.http_adapter` rather than
      hard-coding 3. Run `uv run pytest tests/unit/test_http_adapter.py -k ProbeDelay` and confirm
      failures (no sleep awaited today).
- [x] T004 Implement the guarded sleep in `HttpAgentAdapter._probe_discover`
      (`ziran/infrastructure/adapters/http_adapter.py`) per plan §2: `enumerate` the probes,
      `if index and delay: await asyncio.sleep(delay)` outside the `try`; keep
      `except ProtocolError: continue`; add one docstring line. T003 passes; T001 still passes;
      `TestProbeDiscoverExtended` and `TestHttpAdapterStreamAndDiscover` pass unmodified.

## Phase 3 - Docs (FR-005)

- [x] T005 [P] `docs/guides/remote-agents.md` `## Retry & Timeout`: add
      `probe_delay: 0.5    # Seconds between discovery probes (0 disables)` after `timeout: 30`,
      and one sentence below the block: 0.5 s default between the three discovery probes, about
      1 s added per discovery run versus earlier releases, `probe_delay: 0` restores back-to-back
      probes.
- [x] T006 [P] `docs/concepts/remote-scanning.md`: add the same YAML line after `timeout: 30` in
      the configuration example.

## Phase 4 - Gates (FR-006, SC-003)

- [x] T007 Run and record real output: `uv run ruff check .`, `uv run ruff format --check .`,
      `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%). `git diff --stat` shows only the
      six files in plan §Project Structure (plus the spec dir and the expected CLAUDE.md
      agent-context churn); `uv.lock` unchanged.
- [x] T008 PR body (against `develop`): what changed, the default-delay behaviour change and the
      `0` opt-out, the follow-up (route probes through `_send_with_retry`), and SC-004 stated as
      unverified offline (no live rate-limited endpoint).

## Dependencies
T001 -> T002 -> T003 -> T004 (T003 needs the field to construct configs with `probe_delay`).
T005/T006 are independent of code and can run any time. T007 after all; T008 last.

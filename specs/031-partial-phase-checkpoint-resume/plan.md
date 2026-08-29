# Implementation Plan: Partial-phase checkpoint resume

**Branch**: `031-partial-phase-checkpoint-resume` | **Date**: 2026-08-29 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/031-partial-phase-checkpoint-resume/spec.md`

## Summary

Checkpoints save state between phases today; a mid-phase crash re-runs the whole
phase. The phase executor already updates the shared `tested_vector_ids` and
`attack_results` live as each vector completes, and resume already excludes
tested vectors when a phase re-enters. The only gap is that the checkpoint is
saved only after a full phase. Fix in three small pieces:
(1) a throttled `FlushThrottle` helper (N completions or K seconds) in
`checkpoint.py`; (2) an optional `on_vector_complete` callback on
`PhaseExecutor.execute`, invoked under the existing result lock after each
vector; (3) scanner wiring that builds and atomically saves the checkpoint from
that callback through the throttle, plus a `--checkpoint-flush-interval` CLI
flag. No format change (partial resume rides the existing fields), no new
dependency.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (existing `CampaignCheckpoint`), stdlib `os`/`time`/`asyncio`, Click (CLI). No new dependencies.
**Storage**: Local JSON checkpoint at `{output_dir}/.checkpoint.json` (existing); atomic write via temp-file + `Path.replace` (`os.replace`).
**Testing**: pytest (`@pytest.mark.unit`, `@pytest.mark.integration`); existing `tests/unit/application/test_checkpoint.py`, `tests/integration/test_campaign.py`.
**Target Platform**: Linux/macOS CLI + library.
**Project Type**: Single project (hexagonal: domain / application / infrastructure / interfaces).
**Performance Goals**: Incremental write overhead < 5% of phase duration, achieved by throttling flushes (not per-vector).
**Constraints**: mypy strict, ruff clean, line length 100, coverage >= 85%.
**Scale/Scope**: One helper class + one callback param + scanner/CLI wiring; ~1 new source concept, three touched source files, plus tests and one guide doc.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Hexagonal Architecture** - PASS. All changes stay in the application layer (`agent_scanner/`) and the CLI interface layer. The checkpoint stays a local-file concern behind `CheckpointManager`; no new cross-layer dependency.
- **II. Type Safety** - PASS. New `FlushThrottle` and the `on_vector_complete: Callable[[], None] | None` param are fully annotated; no untyped dicts for domain data. mypy strict must pass.
- **III. Test Coverage** - PASS. New unit tests (throttle bounds, callback invocation) plus an integration test (simulated crash -> resume skips completed vectors). Coverage >= 85%.
- **IV. Async-First** - PASS. The callback is a plain sync function invoked from inside the executor's existing `asyncio.Lock` critical section; file IO is already synchronous in `CheckpointManager.save` and is throttled so it does not stall the loop measurably.
- **V. Extensibility via Adapters** - PASS. `on_vector_complete` is an optional hook; default `None` preserves the existing interface and behaviour for all callers.
- **VI. Simplicity** - PASS. Reuses `CheckpointManager.save`/`build_checkpoint` unchanged; adds one tiny stateful helper and one callback rather than a new checkpoint subsystem. No format change.

No violations -> Complexity Tracking not required.

## Project Structure

### Documentation (this feature)

```text
specs/031-partial-phase-checkpoint-resume/
|-- plan.md    # This file
|-- spec.md    # Feature specification
`-- tasks.md   # Ordered work breakdown
```

### Source Code (repository root)

```text
ziran/application/agent_scanner/
|-- checkpoint.py       # ADD FlushThrottle helper (N-completions / K-seconds)
|-- phase_executor.py   # ADD on_vector_complete callback param; call it under the result lock
`-- scanner.py          # WIRE throttled flush callback into run_campaign; add checkpoint_flush_interval param

ziran/interfaces/cli/
`-- main.py             # ADD --checkpoint-flush-interval option; pass through to run_campaign

tests/
|-- unit/application/test_checkpoint.py    # FlushThrottle bounds
|-- unit/application/test_phase_executor_checkpoint.py  # callback fired per completed vector
`-- integration/test_partial_phase_resume.py           # crash mid-phase -> resume skips completed

docs/guides/
`-- long-running-campaigns.md   # operator guide: resume + flush interval + overhead note
```

**Structure Decision**: Single-project hexagonal layout (existing). Logic lives
in the application layer (`agent_scanner/`); the CLI flag is the only interface
change; tests mirror the existing structure.

## Complexity Tracking

No constitution violations - section intentionally empty.

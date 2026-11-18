# Implementation Plan: remove the web backend, the `ui` extra and `ziran ui`

**Branch**: `chore/083-remove-web-backend` | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ c7da589

## Summary

Add a `streaming` extra so WebSocket targets no longer depend on the `ui` extra. Cut the two
non-web tests loose from web imports and reword the two graph-style comments. Then delete
`ziran/interfaces/web/`, the `ui` extra, the web-only mypy overrides and the web-only tests, and
replace `ziran ui` with a hidden stub that prints where the UI went and exits 2. Relock.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: Click, stdlib `tomllib`. No new dependencies; `websockets` moves from
`ui` to the new `streaming` extra with the same range, and `fastapi` and `uvicorn` move to the
dev-only `test` group for the promptfoo live-server integration test.
**Storage**: none. The Alembic migrations go with the web package.
**Testing**: pytest. `tests/unit/test_ws_handler.py` (extra metadata and import path),
`tests/unit/test_cli_smoke.py` (stub), `tests/unit/test_cicd_suppressions.py` and
`tests/unit/test_phase_graph_persistence.py` (trimmed).

## Constitution Check

- Hexagonal architecture: removes one driving adapter (`interfaces/web`); no inner layer
  imported it (checked with `grep -rn "interfaces.web" ziran`).
- Type safety: the stub is annotated; mypy strict runs in the default and dev-only envs.
- Tests: test first for the extra and the stub; markers on every test.
- Simplicity: the stub is one Click command; no new module.

## Code trace (develop @ c7da589)

- `ws_handler.py` `_ensure_connected`: lazy `import websockets`; an `ImportError` becomes a
  `ProtocolError` that names `pip install ziran[streaming]`.
- `main.py` `ui_cmd` (line 2830): imports `uvicorn` and `ziran.interfaces.web.app`.
- `test_cicd_suppressions.py::TestFingerprints::test_attack_fingerprint_pinned`: the only web
  use is `findings_extractor._compute_fingerprint is attack_fingerprint`.
- `test_phase_graph_persistence.py`: three tests build `PhaseResultRow` and
  `PhaseResultSchema`; one checks `run_manager`'s `or None`; one checks
  `AttackKnowledgeGraph.export_state()` only grows. Only the last is ziran's own graph state.

## Out of scope (other items)

- #521: `ui/`, `hatch_build.py`, the Dockerfile and docker-compose, the Node CI steps, and the
  `.gitignore` line for `ziran/interfaces/web/static/`.
- #523: README, docs, roadmap and specs.

# Tasks: linear-time provenance patterns and reserved metadata keys

**Input**: [spec.md](spec.md), [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Differential and timing tests in `tests/unit/test_provenance_linear.py`
- [x] T002 Strip tests (HTTP invoke and stream, executor single, streaming, multi-turn) and the
  constant test in `tests/unit/test_reserved_metadata.py`
- [x] T003 Run red: the 1 MB tests killed by a 20 s alarm; the strip tests fail on import

## Phase 2: implementation

- [x] T004 Rewrite the CamelCase, mail and domain patterns; drop empty findall items in `atoms()`
- [x] T005 `RESERVED_METADATA_KEYS` and `drop_reserved()`; strip in `HttpAgentAdapter`,
  `AttackExecutor` and `TacticExecutor`

## Phase 3: checks

- [x] T006 Run green; ruff, ruff format, mypy, the full unit suite with coverage

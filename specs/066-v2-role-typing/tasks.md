# Tasks: V2 role typing as an added chain class

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Write `tests/fixtures/chains/study_v1_chains.json` from the `study-v1` export (plan.md)
- [x] T002 Write `tests/unit/test_role_typing.py`: name rules, overrides, typed chains, acceptance 4 and 5
- [x] T003 Write `tests/unit/test_role_typing_probe_parity.py`: the probe's code as oracle, literal and seeded parity
- [x] T004 Write `tests/integration/test_chain_study_v1_equality.py`: study-v1 equality on agents and pattern pairs
- [x] T005 Run the three red (module `role_typing` missing)

## Phase 2: implementation

- [x] T006 Add `ziran/application/knowledge_graph/role_typing.py` (lists verbatim from the probe)
- [x] T007 Add `DangerousChain.typed`
- [x] T008 Add `typed` and `role_overrides` to `ToolChainAnalyzer`; find typed chains after the table's
- [x] T009 Run the three green

## Phase 3: checks and records

- [x] T010 Diff the test oracle against `g10_dev_probe.py` at `f80204a`
- [x] T011 Count study-v1 and typed chains on the 13 dev agents; compare with the probe's `agents_with_chain`
- [x] T012 Run the benchmark regression gate and the ground-truth benchmark, typed off and on
- [x] T013 Confirm the four frozen files are byte-identical to `study-v1`
- [x] T014 ruff check, ruff format, mypy strict, the full test suite with coverage
- [x] T015 Record the change in `CLAUDE.md`

# Tasks: `ziran scan --attacker-model`

- [x] T001 Write `tests/unit/test_cli_attacker_model.py` and run it red (5 failed).
- [x] T002 Add `runnable` to `ziran/application/attacks/pair.py` (FR-003).
- [x] T003 Call it in `PhaseExecutor.execute`; expose `AttackExecutor.attacker` (FR-003).
- [x] T004 Add `--attacker-model` to `ziran scan`, the missing-extra error and the price check
      (FR-001, FR-002, FR-004).
- [x] T005 Print result warnings after the scan summary (FR-005).
- [x] T006 Move `tests/unit/test_negotiation_goals.py` to the not-run contract.
- [x] T007 Update docs: attack vectors, CLI reference, runtime config, example 29.
- [x] T008 Run the touched tests on 3.11, 3.12 and 3.13, ruff check, ruff format, mypy strict.
- [x] T009 Fix round 1: assert the attacker ledger entry (1 call, 80 tokens), a small token cap
      ending in `pair.stop == "budget"`, blank flag off, dry-run filter, readable build errors,
      the not-run line dedupe (FR-006, FR-007).

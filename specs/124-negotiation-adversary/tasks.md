# Tasks: adversarial counterpart scenarios for negotiating agents

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: goals

- [x] T001 Write failing tests for the limit, threshold and secret goals and their validation
  (`tests/unit/test_negotiation_goals.py`); run red.
- [x] T002 Add `LimitBreachGoal`, `SecretLeakGoal`, `amount`/`threshold` and the `GoalCall` roles
  (`ziran/domain/entities/goal.py`).
- [x] T003 Reject a secret the vector sends itself (`ziran/domain/entities/attack.py`).
- [x] T004 Judge the new kinds, reading `output` when a call has no arguments
  (`ziran/application/goals/judge.py`).

## Phase 2: recording

- [x] T005 Record each reply's text on the single, tactic, PAIR and carrier paths.
- [x] T006 Update the `_run` stubs in `tests/unit/application/test_trials.py` to the new signature.

## Phase 3: scenarios

- [x] T007 Write the nine scenarios (`examples/29-negotiation-agent/vectors/negotiation.yaml`).
- [x] T008 Acceptance tests 1 to 3 from the YAML, acceptance 2 over the A2A adapter, and a scan
  through `AgentScanner`.

## Phase 4: docs and gates

- [x] T009 Document the goals (`docs/concepts/attack-vectors.md`) and the example README.
- [x] T010 ruff check, ruff format, mypy strict, touched tests on Python 3.11, 3.12 and 3.13.

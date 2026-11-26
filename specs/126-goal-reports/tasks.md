# Tasks: goal state in every report and in ziran ci

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Write failing tests for `goal_rows`, the three reports, the gate, `ziran ci`, the
  goal type and the trials row (`tests/unit/test_goal_reports.py`); run red.

## Phase 2: implementation

- [x] T002 `AttackResult.goal_type`, set by `judge_goal`.
- [x] T003 `GoalRow` and `goal_rows` (`ziran/domain/entities/goal.py`).
- [x] T004 Markdown summary row and table; `goal_summary` (`ziran/interfaces/cli/reports.py`).
- [x] T005 HTML section, escaped (`ziran/interfaces/cli/html_report.py`).
- [x] T006 Console row and table; `ziran ci` goal lines and the SARIF refusal
  (`ziran/interfaces/cli/main.py`).
- [x] T007 `fail_on_goal_met` and the `goal_met` violation (`ci.py`, `gate.py`).
- [x] T008 A goal met on any trial shows on the combined row (`trials.py`).
- [x] T009 Update the spec 116 test that compared rows without the goal fields.

## Phase 3: docs and gates

- [x] T010 Document the reports and the gate key (`attack-vectors.md`, `cicd-integration.md`).
- [x] T011 ruff check, ruff format, mypy strict, touched tests on Python 3.11, 3.12 and 3.13.

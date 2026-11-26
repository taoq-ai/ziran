# Implementation Plan: goal state in every report and in ziran ci

**Branch**: `feat/126-goal-reports` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2, Rich, Click; no new dependency.

## Approach

1. `ziran/domain/entities/attack.py`: `AttackResult.goal_type: str | None`.
   `ziran/application/goals/judge.py`: `judge_goal` sets it from `attack.goal.type`.
2. `ziran/domain/entities/goal.py`: `GoalRow` (vector id, state, evidence) and
   `goal_rows(attack_results)`, the one reader every format and the gate use. Evidence is raw
   text (`turn 3: submit_offer commitment at $.price`); each renderer escapes it.
3. `ziran/interfaces/cli/reports.py`: `goal_summary(rows)`, the `Goals Met` summary row and the
   Side-Effect Goals table in code spans (`md_code`).
4. `ziran/interfaces/cli/html_report.py`: a Side-effect goals section beside the chain-targets
   section, every cell through `_esc` (`html.escape` of `printable`). The report has no CSP
   meta tag today; none is added or removed.
5. `ziran/interfaces/cli/main.py`: `_display_results` adds the summary row and a table through
   `term`; `ci` prints each met or unmeasured goal through `printable`, and refuses a SARIF with
   `fail_on_goal_met: true`.
6. `ziran/domain/entities/ci.py`: `fail_on_goal_met: bool = False`.
   `ziran/application/cicd/gate.py`: one `goal_met` violation per met goal.
7. `ziran/application/agent_scanner/trials.py`: `combine` sets `goal_met` and `goal_evidence`
   from the first trial whose goal was met.
8. Docs: `docs/concepts/attack-vectors.md` (the reports and `goal_type`),
   `docs/guides/cicd-integration.md` (the gate key, the SARIF refusal).

## Constitution check

Hexagonal: the reader is in the domain, the gate in application, rendering in interfaces.
Types: Pydantic `GoalRow`, mypy strict. Simplicity: one reader, no new abstraction or flag.

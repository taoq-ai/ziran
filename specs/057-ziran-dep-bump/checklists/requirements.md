# Requirements quality checklist: 057-ziran-dep-bump

**Purpose**: check that the spec's requirements are complete, clear and testable before the lock
changes.
**Created**: 2026-10-10
**Feature**: [spec.md](../spec.md)

## Completeness
- [x] CHK001 Is every package whose version changes named with its from and to version? [Spec FR-001 to FR-004]
- [x] CHK002 Is the reason for each forced transitive move stated with its source metadata? [Plan, "Why each package moves"]
- [x] CHK003 Is the case where `pyproject.toml` blocks the fix addressed? [Spec Edge cases: no bound blocks it]

## Clarity
- [x] CHK004 Is "nothing else moves" defined as a measurable comparison? [Spec SC-002]
- [x] CHK005 Is the audit command defined by reference to the CI job, ignore list included? [Spec US1, FR-006]

## Consistency
- [x] CHK006 Do spec FRs, plan table and tasks name the same four versions? [Spec, Plan, Tasks T003]
- [x] CHK007 Does the chosen langgraph version avoid yanked releases? [Spec Edge cases, FR-003]

## Coverage
- [x] CHK008 Are the code paths that use a moved package covered by a named test? [Spec US3: LangGraph adapter tests; ws_handler tests for websockets]
- [x] CHK009 Is the frontend lockfile change bounded to source-map-js, with `ui/package.json` unchanged? [Spec FR-005]

## Assumptions
- [x] CHK010 Is each two-way choice (langgraph patch, sdk patch, websockets downgrade, spec dir name) recorded with what would overturn it? [Spec Assumptions]

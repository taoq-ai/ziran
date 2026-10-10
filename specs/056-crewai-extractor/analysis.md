# Specification analysis: 056-crewai-extractor

Inputs: spec.md, plan.md, tasks.md and `.specify/memory/constitution.md` (1.1.0) at the spec commit.

## Findings

| Id | Category | Severity | Location | Summary | Recommendation |
| --- | --- | --- | --- | --- | --- |
| A1 | Inconsistency | LOW | spec.md US1.3 | JSON exit code also depends on Python findings in crew.py, which the Python analyzer reads as before. | Keep fixture crew.py files free of Python findings; tests assert CR rows, not total counts. |
| A2 | Ambiguity | LOW | spec.md FR-009 | A crew.py or tasks.yaml failure puts one CR000 row on every unit of the project, so N units give N rows for one file problem. | Accept: each unit is affected, and the row carries the unit name. Noted in the PR. |
| A3 | Underspecification | LOW | plan.md section 2 step 4 | "First call to Agent/Task" is in `ast.walk` order (breadth first). A method that builds two Agent calls is read from the first. | Accept; record in the loader docstring. |
| A4 | Inconsistency | LOW | spec.md header vs brief | The brief names `specs/056-crewai-project-audit/`; the workflow hooks look for `specs/*-crewai-extractor`. | Use `056-crewai-extractor`; recorded under Assumptions. |
| A5 | Coverage | LOW | spec.md FR-003 | `MemoryError` is not caught. Inputs are capped at 1 MiB, so a parse cannot allocate without bound. | Accept. |
| A6 | Inconsistency | LOW | spec.md FR-007 | FR-007 was revised after implementation: a name bound by simple assignments to one callee resolves to it, and other elements are kept as source text instead of a unit error. US2.6, US3.8, US3.9 and the Assumptions changed with it. | Covered by T007a; the hostile-input test for `*base` now asserts the text form. |

## Coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 discovery | T005, T007 |
| FR-002 safe_load and ast only | T006, T007 |
| FR-003 bounds and errors | T006, T007 |
| FR-004 agent tools | T005, T007 |
| FR-005 tasks | T005, T007 |
| FR-006 union | T003, T004, T005 |
| FR-007 tool names | T005, T006, T007, T007a |
| FR-008 shared chains | T001, T002 |
| FR-009 findings | T008, T009 |
| FR-010 JSON | T010, T011, T012 |
| FR-011 sampler | T013, T014 |
| FR-012 docs | T015 |

Every requirement has a task; every task maps to a requirement or a gate (T016).

## Constitution

I to VI pass (plan.md Constitution Check). No new dependency. mypy strict covers the new modules.
No CRITICAL or HIGH finding; implementation can proceed.

## Metrics

Requirements 12, tasks 17, coverage 100%, ambiguities 1, duplications 0, critical issues 0.

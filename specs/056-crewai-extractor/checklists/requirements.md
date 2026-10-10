# Requirements quality checklist: static CrewAI project reader

**Purpose**: check that the spec's requirements are complete, clear and testable before code.
**Created**: 2026-10-10
**Feature**: [spec.md](../spec.md)

## Completeness

- [x] CHK001 Discovery rules name every case: directory, agents.yaml file, missing tasks.yaml, skip directories (FR-001, Edge Cases).
- [x] CHK002 Every source of agent tools and task tools is named with its precedence (FR-004, FR-005).
- [x] CHK003 Every file-level and element-level failure has a stated outcome (US2, Edge Cases).
- [x] CHK004 The JSON shape lists every key of a unit (FR-010, plan.md section 5).

## Clarity

- [x] CHK005 "Matching @agent method" is defined (config key, else method name) (FR-004).
- [x] CHK006 Tool-name extraction is defined per AST node kind (FR-007).
- [x] CHK007 Union order is defined (US3.7).

## Trust boundary

- [x] CHK008 No import, exec or eval of project code is a requirement with a test (FR-002, US2.1).
- [x] CHK009 Size, depth, containment and decode bounds are stated with values (FR-003).
- [x] CHK010 Messages hold no file content (US2.8).

## Testability

- [x] CHK011 Each user story has an independent test.
- [x] CHK012 The sampler's determinism has a test (US4.1).
- [x] CHK013 Existing behaviour is protected by unmodified tests (US5, SC-002).

## Scope

- [x] CHK014 MCP client configs, chain patterns and the classifier are untouched.
- [x] CHK015 No new dependency (SC-004).

## Notes

- Analysis findings A1 to A5 are LOW and accepted (analysis.md).

# Requirements checklist: map read_secrets and execute_command to existing chain capabilities

- [x] Each functional requirement has an acceptance scenario or task (FR-001 US1 and US2,
      FR-002 US3, FR-003 task T003, FR-004 SC-003).
- [x] Both target capabilities are existing pattern sides (`secrets_manager`, `execute_code`).
- [x] `chain_patterns.yaml` is unchanged.
- [x] The aliases use the anchored match from spec 056; `mcp__` ids are not mapped.
- [x] The spec states that both aliases are post-hoc for the ziran-paper study.
- [x] Tests use only synthetic in-memory graphs.
- [x] Dev checks open dev scenario files only; no held-out scenario is scored, printed or opened.
- [x] No new dependency.

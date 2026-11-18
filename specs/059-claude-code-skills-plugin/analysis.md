# Specification analysis report: 059-claude-code-skills-plugin

Artifacts: spec.md, plan.md, tasks.md, checklists/requirements.md. Constitution:
`.specify/memory/constitution.md` (1.1.0).

## Findings

| ID | Category | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| A1 | Coverage | MEDIUM (resolved) | spec.md FR-004 | The plan item names only `chain_patterns.yaml`, but `ziran audit` also reports `unrestricted_execution`, hard-coded in `chain_analyzer.py`. A table built from the YAML alone would miss a type users see. | Resolved: FR-004 and the coverage test include the `vulnerability_type="..."` literals in `chain_analyzer.py`; the table has a row. |
| A2 | Coverage | MEDIUM (resolved) | plan.md "Parse only code" | The first parser checked flags only inside a full `ziran <command>` line. A scratch rename of `--max-cost` passed because the skill names it alone in a bullet. | Resolved: flags named alone must be options of a command the same file invokes; self-test and a scratch rename prove it. |
| A3 | Inconsistency | LOW | spec.md Edge Cases | `ziran scan --help` shows `--phases reconnaissance trust_building`, which Click rejects (`multiple=True`). | Skills repeat the flag; the checker uses Click's parser and reports leftover arguments. Fixing the CLI help text is outside this item (no change under `ziran/`); listed as a candidate. |
| A4 | Ambiguity | LOW | spec.md Assumptions | Plugin version `0.1.0` is independent of the package; Claude Code refreshes an installed plugin only when the version changes. | Recorded as an assumption; the plugin README tells maintainers to bump it. Release-please `extra-files` is a follow-up. |
| A5 | Underspecification | LOW | spec.md US3.3 | "No network" for the dry run: the example target is `localhost:8899`, which the adapter probes. | Edge case records it: the probe stays on the host and is refused when nothing listens. |
| A6 | Coverage | LOW | tasks.md T009 | The GitHub-shorthand install can be checked only once the branch is on GitHub. | T009 runs then; its result goes in the PR body. |

No open CRITICAL or HIGH findings.

## Coverage

| Requirement | Tasks |
|---|---|
| FR-001 marketplace | T002, T007 |
| FR-002 plugin manifest | T002, T007 |
| FR-003 skills | T001, T004 |
| FR-004 ATLAS table | T001, T003 |
| FR-005 threat model without ziran | T004 |
| FR-006 drift test | T001, T006 |
| FR-007 README | T005 |
| FR-008 no runtime change | T008 |
| SC-001 strict validation | T007 |
| SC-002 isolated install | T007, T009 |
| SC-003 drift test red on rename | T006 |
| SC-004 gates | T008 |

Requirements: 8. Success criteria: 4. Tasks: 9. Requirements with at least one task: 8 of 8.

## Constitution alignment
No conflict. Principle III: one `@pytest.mark.unit` module, run red before the plugin files
existed (16 failed, 4 passed) and green after. Principle VI: no dependency, no helper module, no
runtime code. Principle I: nothing under `ziran/` changes.

## Next actions
Proceed to the draft PR (T009).

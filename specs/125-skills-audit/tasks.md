# Tasks: spec 125

- [x] T001 `tests/unit/test_claude_code_skills.py` (loader, hostile inputs, audit, CLI, SARIF); run red (29 failed, 2 passed vacuously)
- [x] T002 `ClaudeCodeSkill`, `ClaudeCodeSkillFile`, `ClaudeCodeScan.skills`; loader discovery, shared frontmatter helper, bounded bundled walk
- [x] T003 Audit: skill label, no-key means no tool, bundled Python through `StaticAnalyzer`, `CC002`, `atlas`; baseline pass-through; SARIF and JSON `atlas`; directory pass skips skill folders; run green
- [x] T004 `docs/reference/cli.md` Agent Skills section and `CC002` row; `audit` help text
- [x] T005 Audit `examples/*`, `plugins/ziran` and its `SKILL.md` files before and after, and diff
- [x] T006 ruff check, ruff format --check, mypy strict; touched tests on 3.11, 3.12, 3.13

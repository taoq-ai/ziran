# Tasks: ziran Claude Code plugin with four skills and a CLI drift test

Base: `develop` @ 5c3f90c. Test first: T001 runs red before any plugin file exists.

## Phase 1 - Drift test (FR-006; US2, US3)

- [x] T001 Write `tests/unit/test_claude_plugin_skills.py`: frontmatter, CLI references, checker
      self-test, action inputs, ATLAS coverage, audit/triage/scan offline runs. Run
      `uv run pytest tests/unit/test_claude_plugin_skills.py` and see it fail (no skills yet).

## Phase 2 - Plugin (FR-001 to FR-005; US1, US2, US3)

- [x] T002 Add `.claude-plugin/marketplace.json` and `plugins/ziran/.claude-plugin/plugin.json`.
- [x] T003 Add `plugins/ziran/skills/threat-model-agent/references/atlas-chains.md` covering all
      chain types in `chain_patterns.yaml`.
- [x] T004 Add the four `SKILL.md` files and `plugins/ziran/README.md`. T001 passes.
- [x] T005 Add the README install section (FR-007).

## Phase 3 - Evidence and gates (SC-001 to SC-004)

- [x] T006 Rename a flag in a scratch copy of a skill and confirm the test fails naming the file
      and flag (SC-003).
- [x] T007 `claude plugin validate --strict .` and `plugins/ziran` from a `git archive` of the
      head; isolated `CLAUDE_CONFIG_DIR` install and `claude plugin details ziran@ziran` (SC-001,
      SC-002).
- [x] T008 Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran`; confirm `git diff --stat origin/develop -- ziran/` is empty.
- [x] T009 Push, open the draft PR to `develop`, then install via the GitHub shorthand of the
      pushed branch in an isolated `CLAUDE_CONFIG_DIR`.

## Phase 4 - Review fixes, round 1 (FR-009)

- [x] T010 Add the untrusted-content rule to three skills and a test that asserts it (red: 3
      failed before the skill edits); `SA001` no-repeat note; `claude plugin validate` tests
      marked `integration`; explicit single element for the implicit concatenation in the
      checker self-test.

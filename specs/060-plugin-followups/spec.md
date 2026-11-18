# Feature Specification: Claude Code plugin follow-ups from PR #470

**Feature Branch**: `fix/060-plugin-followups`
**Created**: 2026-10-18
**Status**: Active
**Base**: `develop` @ 90dc65b (PR #470, spec 059, merged).
**Scope**: four non-blocking review follow-ups from spec 059. One docstring line under `ziran/`
changes; everything else is release config, skill Markdown and the existing drift test.

## Promise in my words

The plugin from spec 059 reaches installed users when it changes, treats every piece of target
text it reads as untrusted, and never shows a command or workflow line that is broken or can be
silently retargeted.

## Requirements

- **FR-001 (plugin version follows releases)**: `release-please-config.json` lists
  `plugins/ziran/.claude-plugin/plugin.json` (`$.version`) under `extra-files`, so every ziran
  release sets the plugin version. Claude Code updates an installed plugin only when its version
  changes, so without this skill edits never reach installed users. This supersedes spec 059's
  "independent `0.1.0`" decision. The plugin README stops telling contributors to bump by hand.
- **FR-002 (untrusted discover output)**: `set-up-scan/SKILL.md` carries the same untrusted-content
  rule as the other three skills, scoped to `ziran discover` output (tool names, descriptions and
  parameters the target reports about itself). `test_skill_treats_read_content_as_untrusted`
  covers all four skills.
- **FR-003 (scan help example)**: the `ziran scan --help` example that passes two values to one
  `--phases` (Click rejects it) repeats the flag. A test parses every `ziran ...` example in the
  scan help with the drift test's Click checker.
- **FR-004 (action pinned to a SHA)**: the GitHub Action snippet in `audit-agents/SKILL.md` uses
  `taoq-ai/ziran@<40-hex SHA>  # vX.Y.Z` for the same release as its `ziran-version` pin
  (v0.42.0, `b813e4f`). A tag can be moved; a SHA cannot. The test asserts a full SHA and that the
  comment version equals `ziran-version`.

## Out of scope

- `@v0` in `README.md` and `docs/guides/*`: product docs, not the skill; left to a docs change.
- `ziran init` writes a `ziran.yaml` that `ziran scan` never reads. Wiring config into `scan` is a
  feature, not a follow-up; raised in the PR as a separate issue.

## Success criteria

- **SC-001**: without the skill, CLI and snippet edits the extended tests fail (3 failures); with
  them, `tests/unit/test_claude_plugin_skills.py` passes.
- **SC-002**: quality gates pass (ruff check, ruff format --check, mypy strict, pytest --cov >= 85%).

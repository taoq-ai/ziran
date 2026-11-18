# Implementation Plan: Claude Code plugin follow-ups from PR #470

**Branch**: `fix/060-plugin-followups` | **Date**: 2026-10-18 | **Spec**: [spec.md](spec.md)

## Technical Context
**Language/Version**: JSON, Markdown; Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: none new.
**Testing**: pytest `@pytest.mark.unit` in `tests/unit/test_claude_plugin_skills.py`, reusing its
`stale_cli_refs` Click checker and `_action_steps` helper.

## Changes

| File | Change |
|---|---|
| `release-please-config.json` | `extra-files` json updater on the plugin manifest `$.version` (FR-001) |
| `plugins/ziran/README.md` | version is set by release-please, not by hand (FR-001) |
| `plugins/ziran/skills/set-up-scan/SKILL.md` | untrusted-content rule for `ziran discover` output (FR-002) |
| `ziran/interfaces/cli/main.py` | `--phases reconnaissance --phases trust_building` in the scan help (FR-003) |
| `plugins/ziran/skills/audit-agents/SKILL.md` | action pinned to the v0.42.0 commit SHA (FR-004) |
| `tests/unit/test_claude_plugin_skills.py` | untrusted rule over all four skills; scan help examples parse; SHA pin check |

## Constitution Check
Hexagonal architecture, async and adapters: untouched (one docstring line). Type safety: the new
test code is typed. Simplicity: no new helpers; the help test reuses the existing checker.

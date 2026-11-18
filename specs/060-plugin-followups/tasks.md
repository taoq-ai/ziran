# Tasks: Claude Code plugin follow-ups from PR #470

Base: `develop` @ 90dc65b (PR #470 merged).

- [x] T001 Extend the drift test: untrusted rule over all four skills, scan help examples parse,
      action SHA pin. Run against the unfixed files: 3 failed (SC-001).
- [x] T002 FR-001: release-please `extra-files`; plugin README wording.
- [x] T003 FR-002: untrusted-content rule in `set-up-scan/SKILL.md`.
- [x] T004 FR-003: repeat `--phases` in the `ziran scan --help` example.
- [x] T005 FR-004: pin the action to `b813e4f` (v0.42.0) in `audit-agents/SKILL.md`.
- [x] T006 Quality gates: `uv run ruff check .`, `uv run ruff format --check .`,
      `uv run mypy ziran/`, `uv run pytest --cov=ziran`.
- [ ] T007 Rebase on `develop` after #470 merges, push, open the PR to `develop`, CI green.

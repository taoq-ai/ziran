# Implementation Plan: Adopt release-please for Automated Release Management

**Branch**: `ci/001-release-please-automation` | **Date**: 2026-03-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-release-please-automation/spec.md`

## Summary

Replace the manual tag-push release workflow with release-please to automate versioning, changelog generation, and release PR creation. Uses the `simple` release type to avoid conflicts with hatch-vcs (which derives versions from git tags). The existing `release.yml` publish pipeline stays unchanged — release-please creates the tags that trigger it.

## Technical Context

**Language/Version**: N/A (CI configuration only — YAML, JSON)
**Primary Dependencies**: release-please-action v4 (GitHub Action)
**Storage**: N/A
**Testing**: Manual validation via dry-run on branch
**Target Platform**: GitHub Actions
**Project Type**: CI/CD configuration
**Performance Goals**: Release PR created/updated within GitHub Actions run time (~2 min)
**Constraints**: Must not modify existing `release.yml`; must produce tags compatible with hatch-vcs (`v`-prefixed)
**Scale/Scope**: 3 new files, 0 modified files

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal Architecture | N/A | No application code |
| II. Type Safety | N/A | No Python code |
| III. Test Coverage | N/A | No testable code |
| IV. Async-First | N/A | No I/O code |
| V. Extensibility via Adapters | N/A | No adapter changes |
| VI. Simplicity | Pass | Minimal config files, no abstractions |
| Quality Gates | Pass | Existing pipeline unchanged |
| Governance | Pass | Conventional Commits enforced; branch follows `type/NNN-name` |

**Post-design re-check**: All gates still pass. No violations.

## Project Structure

### Documentation (this feature)

```text
specs/001-release-please-automation/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0: research findings
├── data-model.md        # Phase 1: entity definitions
├── quickstart.md        # Phase 1: usage guide
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code (repository root)

```text
.github/workflows/
├── release.yml              # EXISTING — not modified
└── release-please.yml       # NEW — release-please workflow

release-please-config.json   # NEW — release-please configuration
.release-please-manifest.json # NEW — version manifest (bootstrapped at current version)
CHANGELOG.md                  # NEW — auto-generated changelog (created by first release PR)
```

**Structure Decision**: Three new files at repo root + one new workflow file. Zero modifications to existing files.

## Key Technical Decisions

### 1. `release-type: "simple"` (not `"python"`)

The `"python"` strategy updates `pyproject.toml` version field, which conflicts with hatch-vcs (`dynamic = ["version"]`). The `"simple"` strategy only manages `CHANGELOG.md` and the manifest. hatch-vcs reads the version from the git tag at build time — no file-level version tracking needed.

### 2. Token for downstream workflow triggering

Tags created by `GITHUB_TOKEN` do not trigger other GitHub Actions workflows (anti-recursion safeguard). Since `release.yml` triggers on tag push, we need a token that can trigger workflows:

- **Option A**: PAT stored as `RELEASE_PLEASE_TOKEN` repository secret
- **Option B**: GitHub App token via `actions/create-github-app-token`
- **Option C**: Move publish steps into the release-please workflow, keyed on `release_created`

Recommended: Start with Option A (simplest), migrate to Option B later for better security.

### 3. Tag format: `v0.14.0`

`include-v-in-tag: true` and `include-component-in-tag: false` produces tags like `v0.14.0`, which matches:
- The existing `release.yml` trigger pattern: `v[0-9]+.[0-9]+.[0-9]+`
- hatch-vcs/setuptools-scm default tag format
- The existing tag history (`v0.13.0`, `v0.12.0`, etc.)

### 4. Changelog sections

Visible: Features, Bug Fixes, Performance Improvements
Hidden: refactor, docs, test, chore, ci, build

Breaking changes are always shown regardless of section visibility.

## Complexity Tracking

No constitution violations to justify. This is a minimal CI configuration change.

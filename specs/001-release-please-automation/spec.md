# Feature Specification: Adopt release-please for Automated Release Management

**Feature Branch**: `ci/001-release-please-automation`
**Created**: 2026-03-20
**Status**: Active
**Input**: User description: "Adopt release-please for automated release management. Replace manual tag-push workflow with release-please to automate versioning, changelog generation, and release PR creation based on Conventional Commits. Current version is v0.13.0. First release needs bootstrap with release-as to avoid version mismatch."

## Constitution Check

| Principle | Applies? | Status |
|---|---|---|
| I. Hexagonal Architecture | No | N/A — this feature adds CI config files only, no application code |
| II. Type Safety | No | N/A — no Python code changes |
| III. Test Coverage | No | N/A — no testable code; validated by dry-run on branch |
| IV. Async-First | No | N/A — no I/O code |
| V. Extensibility via Adapters | No | N/A — no adapter changes |
| VI. Simplicity | Yes | Pass — minimal config files, no new abstractions |
| Quality Gates | Yes | Pass — existing `release.yml` pipeline unchanged |
| Specification Lifecycle | Yes | Pass — following speckit workflow |
| Governance (Conventional Commits) | Yes | Pass — release-please depends on and enforces this |

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Automated Release PR Creation (Priority: P1)

As a maintainer, I want release-please to automatically create and update a Release PR on every push to `main`, so that I never need to manually decide the next version number or create tags by hand.

**Why this priority**: This is the core value proposition — eliminating the manual, error-prone step of deciding versions and pushing tags. Every other story depends on this working correctly.

**Independent Test**: Can be fully tested by merging a `feat:` commit to `main` and verifying that a Release PR is opened with the correct version bump (minor) and changelog entry.

**Acceptance Scenarios**:

1. **Given** a `feat: add new scanner mode` commit is pushed to `main`, **When** the release-please workflow runs, **Then** a Release PR is created (or updated) proposing a minor version bump (e.g., v0.14.0)
2. **Given** a `fix: correct timeout handling` commit is pushed to `main`, **When** the release-please workflow runs, **Then** a Release PR is created (or updated) proposing a patch version bump (e.g., v0.13.1)
3. **Given** a commit with `feat!:` or `BREAKING CHANGE:` footer is pushed, **When** the release-please workflow runs, **Then** a Release PR is created proposing a major version bump (e.g., v1.0.0)
4. **Given** the Release PR is approved and merged, **When** the merge completes, **Then** release-please creates a git tag (e.g., `v0.14.0`) which triggers the existing `release.yml` publish pipeline

---

### User Story 2 - Automatic Changelog Generation (Priority: P1)

As a maintainer, I want a `CHANGELOG.md` to be automatically generated and kept up to date from commit history, so that users and contributors can see what changed in each release without manual effort.

**Why this priority**: A changelog is essential for open-source projects and users upgrading between versions. Generating it manually is tedious and often skipped.

**Independent Test**: Can be tested by verifying that the Release PR includes a well-structured `CHANGELOG.md` update with entries grouped by type (features, fixes, etc.).

**Acceptance Scenarios**:

1. **Given** multiple commits of different types are on `main` since the last release, **When** the Release PR is created, **Then** the `CHANGELOG.md` in the PR contains entries grouped by category (Features, Bug Fixes, etc.)
2. **Given** a Release PR already exists and new commits land on `main`, **When** the release-please workflow runs again, **Then** the existing Release PR is updated with the new entries appended to the changelog

---

### User Story 3 - First Release Bootstrap (Priority: P1)

As a maintainer, I want the first release-please-managed release to correctly continue from the current version (v0.13.0) without resetting or producing an incorrect version number.

**Why this priority**: Getting the bootstrap wrong would publish a broken version to PyPI or confuse users with a version jump/reset. This is a one-time but critical setup step.

**Independent Test**: Can be tested by verifying that after setup, the first Release PR proposes v0.13.1 or v0.14.0 (depending on commits), not v0.1.0 or v1.0.0.

**Acceptance Scenarios**:

1. **Given** the manifest is bootstrapped with `{"." : "0.13.0"}`, **When** a `fix:` commit lands on `main`, **Then** the Release PR proposes v0.13.1
2. **Given** the manifest is bootstrapped with `{"." : "0.13.0"}`, **When** a `feat:` commit lands on `main`, **Then** the Release PR proposes v0.14.0

---

### User Story 4 - Existing Publish Pipeline Unchanged (Priority: P2)

As a maintainer, I want the existing PyPI publish and GitHub Release workflow (`release.yml`) to continue working exactly as before, triggered by the tags that release-please creates.

**Why this priority**: The publish pipeline is already battle-tested with OIDC trusted publishing, version verification, and TestPyPI for pre-releases. Changing it introduces unnecessary risk.

**Independent Test**: Can be tested by verifying that after a Release PR merge, the tag created by release-please triggers `release.yml` and the full lint → test → build → publish pipeline succeeds.

**Acceptance Scenarios**:

1. **Given** a Release PR is merged and release-please creates tag `v0.14.0`, **When** the tag push event fires, **Then** the existing `release.yml` workflow runs successfully (lint, test, build, publish to PyPI, create GitHub Release)
2. **Given** the existing `release.yml` workflow, **When** comparing its content before and after this feature, **Then** the file is unchanged

---

### Edge Cases

- What happens when a commit message doesn't follow Conventional Commits format? Release-please ignores it — no version bump is proposed for non-conforming commits.
- What happens when release-please and `hatch-vcs`/`setuptools-scm` disagree on the version? The `release.yml` already uses `SETUPTOOLS_SCM_PRETEND_VERSION` from the tag, so the tag is authoritative.
- What happens if someone manually pushes a tag while release-please is active? The manual tag triggers `release.yml` as before; release-please may get confused on the next run. The manifest should be updated to reflect the manually released version.
- What happens if the Release PR is not merged for a long time and many commits accumulate? Release-please continues updating the same PR, aggregating all changes into the changelog.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST run a release-please workflow on every push to the `main` branch
- **FR-002**: The system MUST create or update a Release PR with the correct semantic version bump based on Conventional Commits (fix → patch, feat → minor, breaking → major)
- **FR-003**: The system MUST generate and maintain a `CHANGELOG.md` with entries grouped by commit type
- **FR-004**: The system MUST bootstrap the version manifest at `0.13.0` (or the current version at implementation time) so that the first automated release continues the existing version sequence
- **FR-005**: The system MUST create a git tag when the Release PR is merged, which triggers the existing `release.yml` pipeline
- **FR-006**: The existing `release.yml` workflow MUST NOT be modified
- **FR-007**: The system MUST use the manifest-based release-please configuration (`.release-please-manifest.json` + `release-please-config.json`)
- **FR-008**: The release-please workflow MUST have appropriate GitHub permissions (contents: write, pull-requests: write)

### Key Entities

- **Release PR**: An auto-managed pull request that tracks pending changes and the proposed next version. One active Release PR exists at a time.
- **Version Manifest**: A JSON file (`.release-please-manifest.json`) that records the current released version so release-please knows where to increment from.
- **Release Config**: A JSON file (`release-please-config.json`) that defines the release type, changelog sections, and other release-please behavior.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After merging a Conventional Commit to `main`, a Release PR is created or updated within the workflow run time (typically under 2 minutes)
- **SC-002**: The first release-please-managed release produces the correct next version after v0.13.0, not a reset or unexpected version
- **SC-003**: The `CHANGELOG.md` accurately reflects all changes since the previous release, grouped by type
- **SC-004**: The full release cycle (commit → Release PR → merge → tag → PyPI publish) completes without manual intervention
- **SC-005**: Zero modifications to the existing `release.yml` workflow

## Assumptions

- The project already follows Conventional Commits format (confirmed by existing commit history: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
- The `release-please-action` GitHub Action is the standard way to integrate release-please into GitHub workflows
- The `hatch-vcs` / `setuptools-scm` version derivation in `release.yml` will continue to work because it reads the version from the git tag, not from any file that release-please modifies
- Pre-release versions (alpha, beta, rc) are out of scope for the initial release-please setup and can be added later

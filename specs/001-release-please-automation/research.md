# Research: release-please for Automated Release Management

**Date**: 2026-03-20
**Feature**: 001-release-please-automation

## Decision 1: Release Type

**Decision**: Use `release-type: "simple"`, not `"python"`

**Rationale**: The `"python"` strategy tries to update a static `version` field in `pyproject.toml`, `setup.py`, `__init__.py`, and `version.py`. Ziran uses `hatch-vcs` with `dynamic = ["version"]` — the version is derived from git tags at build time. There is no static version field to update. The `"simple"` strategy only updates `CHANGELOG.md` and the manifest, which is exactly what we need.

**Alternatives considered**:
- `release-type: "python"` — would conflict with hatch-vcs by injecting a `version` field into pyproject.toml
- `release-type: "node"` — wrong ecosystem

## Decision 2: Token Strategy

**Decision**: Use `secrets.GITHUB_TOKEN` initially; evaluate PAT/GitHub App if downstream workflow triggering fails

**Rationale**: Tags and releases created by `GITHUB_TOKEN` do **not** trigger other workflows (GitHub's anti-recursion safeguard). Our existing `release.yml` is triggered by tag pushes. This means release-please's tag creation via `GITHUB_TOKEN` won't trigger the publish pipeline.

Options to resolve:
1. **PAT (Personal Access Token)**: Replace `GITHUB_TOKEN` with a PAT that has `contents:write` and `pull-requests:write` scopes. Tags created by PATs do trigger workflows.
2. **GitHub App token**: Use `actions/create-github-app-token` to generate a token from a GitHub App. More secure than PATs (scoped, short-lived).
3. **Combine workflows**: Move the publish steps into the release-please workflow itself, keyed on `release_created` output. This avoids the token issue entirely but duplicates the publish logic.

**Recommended**: Option 2 (GitHub App) for production, but start with option 1 (PAT stored as `RELEASE_PLEASE_TOKEN` secret) for simplicity. Alternatively, option 3 is the simplest and avoids token management.

## Decision 3: Tag Format

**Decision**: `include-v-in-tag: true`, `include-component-in-tag: false`

**Rationale**: The existing `release.yml` triggers on tag patterns `v[0-9]+.[0-9]+.[0-9]+*`. hatch-vcs/setuptools-scm also expect `v`-prefixed tags. Setting `include-component-in-tag: false` prevents tags like `ziran-v0.14.0` (monorepo format) which would break both.

**Alternatives considered**:
- No `v` prefix — breaks existing release.yml trigger and hatch-vcs conventions
- Component in tag — unnecessary for single-package repo

## Decision 4: Bootstrap Strategy

**Decision**: Use `.release-please-manifest.json` with `{"." : "0.13.0"}` (or current version at implementation time)

**Rationale**: The tag `v0.13.0` already exists in the repo, so release-please can find it as the anchor point. No `bootstrap-sha` needed. Both config files must be committed to `main` before the action runs.

**Alternatives considered**:
- `release-as` flag — one-shot override, less clean than manifest bootstrap
- `bootstrap-sha` — only needed if the tag doesn't exist

## Decision 5: Changelog Sections

**Decision**: Show Features, Bug Fixes, and Performance Improvements. Hide refactor, docs, test, chore, ci, build.

**Rationale**: The changelog should be user-facing. Internal changes (refactoring, CI tweaks, test additions) are noise for users upgrading. Breaking changes are always shown regardless of hidden sections.

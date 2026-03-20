# Data Model: release-please for Automated Release Management

**Date**: 2026-03-20
**Feature**: 001-release-please-automation

## Entities

This feature involves configuration files only — no application-level data models.

### Release Config (`release-please-config.json`)

Root-level JSON object defining release-please behavior:

- `$schema` — JSON schema URL for validation
- `packages` — map of package paths to their config
  - `"."` — root package config
    - `release-type` — strategy (e.g., "simple")
    - `package-name` — package identifier
    - `include-v-in-tag` — whether tags have `v` prefix
    - `include-component-in-tag` — whether tags include package name
    - `changelog-sections` — array of section definitions
      - `type` — conventional commit type
      - `section` — display name in changelog
      - `hidden` — whether to hide from changelog

### Version Manifest (`.release-please-manifest.json`)

Flat JSON object mapping package paths to current version strings:

- `"."` → `"0.13.0"` (updated automatically by release-please after each release)

### Release PR (GitHub)

Managed by release-please, not a file in the repo:

- One active Release PR at a time per package
- Contains changelog updates and version bump
- Merging the PR triggers tag creation

### CHANGELOG.md

Cumulative markdown file with entries per release:

- Release heading with version and date
- Sections grouped by commit type (Features, Bug Fixes, etc.)
- Automatically maintained by release-please

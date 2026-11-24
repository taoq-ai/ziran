# Feature Specification: release hygiene before the next tag

**Feature Branch**: `fix/097-release-hygiene`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: REL-HYGIENE (goal G-5).
**Base**: `develop` @ dfdbe96.

## The promise in our own words

Three small faults would ship with the next release tag. This change fixes all three:

1. Dependabot commit f632dd8 raised the `mcp` extra in `pyproject.toml` to `<3`. The
   `override-dependencies` range and `uv.lock` still say `<2`, so `uv lock --check` fails on
   develop. The extra goes back to `mcp>=1.30,<2`, the range its own comment names. `uv.lock`
   does not change.
2. The CI `lint` job gains a `uv lock --check` step. The next bump that touches only
   `pyproject.toml` then fails its own PR instead of reaching a release.
3. Every `uses:` line in `.github/workflows/release.yml` that names a tag or a branch is pinned
   to the commit that ref names, with the tag in a trailing comment. This covers
   `pypa/gh-action-pypi-publish@release/v1`, a moving branch that runs with the PyPI OIDC token.

Out of scope: other workflows, `action.yml`, the Dependabot config and the chromadb risk
acceptances.

## Acceptance scenarios

1. **Given** the branch head, **When** `uv lock --check` runs in a `git archive` copy, **Then**
   it passes, and the `mcp` extra and `override-dependencies` both read `<2`.
2. **Given** develop dfdbe96's `pyproject.toml` and `uv.lock`, **When** the new lint step runs,
   **Then** it fails; on the branch head it passes.
3. **Given** `release.yml` at the head, **When** every `uses:` line is read, **Then** each names
   a 40-hex commit followed by its tag as a comment, and each commit equals
   `gh api repos/<repo>/commits/<tag> --jq .sha`.
4. **Given** `release.yml` at the head, **When** `actionlint` runs, **Then** it reports nothing.

## Requirements

- **FR-001**: The `mcp` extra reads `mcp>=1.30,<2`.
- **FR-002**: `ci.yml` `lint` runs `uv lock --check` before `uv sync --frozen`.
- **FR-003**: Each `uses:` in `release.yml` matches `<owner>/<repo>@<40-hex> # v<version>`;
  `tests/unit/test_release_workflow.py` asserts it.
- **FR-004**: `actionlint` reports no finding on `release.yml` or `ci.yml`.

## Assumptions

- The trailing comment names the most specific tag at the resolved commit (for example
  `# v7.0.1` for `actions/checkout@v7`), the style the attest pins already use, so Dependabot
  can bump pin and comment together. `release/v1` resolves to the same commit as tag `v1.14.3`.
  Overturned if the owner wants the moving ref (`v7`, `release/v1`) in the comment.
- `actionlint` 1.7.12 reported three SC2086 notes in the `update-action-tag` script on develop.
  Quoting the three `gh api` path arguments clears them with no change in behaviour, since the
  tag and repository values hold no spaces or glob characters.

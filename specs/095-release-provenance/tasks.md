# Tasks: build provenance and SBOM attestations for every release

Base: `origin/develop` @ 2988b9a. Branch `ci/094-release-provenance`. Test first: T001 runs red
before T002.

## Phase 1 - Test

- [x] T001 `tests/unit/test_release_workflow.py`: scopes, needs, no build code, attest modes,
      publish order, SBOM export and attachment.

## Phase 2 - Workflow (FR-001 to FR-005)

- [x] T002 `release.yml` `build`: export and upload the SBOM.
- [x] T003 `release.yml` `attest` job; `publish-pypi` and `publish-testpypi` need it.
- [x] T004 `release.yml` `github-release`: download and attach the SBOM.

## Phase 3 - Policy and proof (FR-006)

- [x] T005 `SECURITY.md`: Supported versions, Reporting a vulnerability, Verifying a release.
- [x] T006 `actionlint` on `release.yml`; the `uv export` command on a `git archive` copy, with
      its package count.

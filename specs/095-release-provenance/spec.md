# Feature Specification: build provenance and SBOM attestations for every release

**Feature Branch**: `ci/094-release-provenance`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: ISSUE-291-PROVENANCE (goal G-5). Closes the open parts of #291.
**Base**: `develop` @ 2988b9a.

## The promise in our own words

A ziran release today carries PyPI's PEP 740 attestations (from Trusted Publishing) and nothing
a user can check against this repository. From the next tag on, each release also carries two
GitHub artifact attestations, signed through Sigstore, that `gh attestation verify` checks:

1. `release.yml` gains an `attest` job after `build`. It downloads the built `dist/` and the
   SBOM, runs no repository or third-party build code (no checkout, no npm, no uv, no `run`
   step at all), and holds only `contents: read`, `id-token: write` and `attestations: write`.
2. It writes a SLSA build provenance attestation over `dist/*` and the SBOM file, and a CycloneDX
   SBOM attestation over `dist/*`.
3. The SBOM is made in `build` by `uv export --format cyclonedx1.5` from the locked runtime
   packages (no new tool).
4. `publish-pypi` and `publish-testpypi` need `attest`, so a failed attestation stops the release
   before anything is published. The workflow's `workflow_dispatch` re-runs a tag once fixed.
5. `github-release` attaches the SBOM beside `dist/*`.
6. A new `SECURITY.md` states the supported versions, how to report a vulnerability through
   GitHub private vulnerability reporting, and how to verify a wheel and the SBOM.

PyPI's own PEP 740 attestations from `pypa/gh-action-pypi-publish@release/v1` stay as they are.

## Acceptance scenarios

1. **Given** `release.yml` at the head, **When** `tests/unit/test_release_workflow.py` runs,
   **Then** `attest` holds exactly the three scopes, needs `build`, has no checkout, npm or uv
   build step, and `publish-pypi` needs it.
2. **Given** `uv export --format cyclonedx1.5` with the release's arguments, **Then** it writes a
   CycloneDX 1.5 JSON document listing ziran's locked runtime packages; the PR body names the
   command and the package count.
3. **Given** `SECURITY.md`, **Then** it has Supported versions, Reporting a vulnerability and
   Verifying a release sections, and the verify command names the repository.
4. **Given** the first release tag after merge, **When** `gh attestation verify` runs on the PyPI
   wheel and on the release's SBOM, **Then** both verify (recorded after that release;
   unmeasured until then).
5. **Given** the PR head, **When** CI runs, **Then** every check passes.

## Requirements

- **FR-001**: `build` writes `sbom/ziran-<tag>.cdx.json` with
  `uv export --preview-features sbom-export --format cyclonedx1.5 --frozen --no-default-groups
  --all-extras` and uploads it as artifact `sbom`.
- **FR-002**: job `attest` needs `build`, holds exactly `contents: read`, `id-token: write`,
  `attestations: write`, and its steps are only SHA-pinned `actions/download-artifact` and
  `actions/attest`.
- **FR-003**: `attest` runs `actions/attest` twice: provenance over `dist/*` and
  `sbom/*.cdx.json`; SBOM over `dist/*` with `sbom-path` the SBOM file.
- **FR-004**: `publish-pypi` and `publish-testpypi` need `attest`.
- **FR-005**: `github-release` downloads `sbom` and uploads `dist/*` and `sbom/*.cdx.json`.
- **FR-006**: `SECURITY.md` at the repository root with the three sections of scenario 3.

## How this fails

1. `attest` fails at the first tag (an Actions or Sigstore change, a missing scope). Then
   nothing publishes; the fix lands on `main` and `workflow_dispatch` with the tag re-runs it.
   The tag stays unpublished until then.
2. `uv export` with the experimental CycloneDX format changes or breaks under `setup-uv`
   `latest`. Then `build` fails before any publish, the same recovery as 1.
3. The SBOM or provenance subjects miss the file a user downloads (for example PyPI rewrites a
   name). The wheel on PyPI is the uploaded file byte for byte, so its digest matches the
   subject; the first release's verify run (scenario 4) proves it.

## Outside

Separate cosign signatures (GitHub attestations are Sigstore-signed already), a README badge,
SLSA level claims, the `pypi` environment's protection rules (owner-only), re-pinning the
workflow's existing tag-pinned actions, releases merged before WUWEI.

## Assumptions

- `actions/attest@v4` replaces the item's `actions/attest-build-provenance` and
  `actions/attest-sbom`. Why: both READMEs (v4.2.2 and v4.1.0) say they are now wrappers on
  `actions/attest` and point new work there; one action does both modes. Overturn: the owner
  wants the wrapper names.
- No `artifact-metadata: write`. Why: `actions/attest` needs it only for storage records, which
  it writes only with `push-to-registry: true` (OCI images). Overturn: a run that fails for
  want of it.
- The SBOM lists all extras and no dependency groups. Why: the wheel can install any extra, and
  dependency groups never ship. Overturn: the owner wants the base install only.
- `publish-testpypi` also waits for `attest`. Why: "before anything is published" covers
  TestPyPI too. Overturn: the owner wants pre-releases to publish without attestation.

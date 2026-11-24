# Implementation Plan: build provenance and SBOM attestations for every release

**Branch**: `ci/094-release-provenance` | **Spec**: [spec.md](spec.md)

## Technical Context

GitHub Actions YAML; Python 3.11+ test (CI matrix 3.11, 3.12, 3.13) with PyYAML, already a
dependency. No new runtime dependencies. Touched: `.github/workflows/release.yml`,
`SECURITY.md`, `tests/unit/test_release_workflow.py`.

Actions, checked against their repositories on 2026-11-24:

| Action | Tag | Commit |
|---|---|---|
| `actions/attest` | v4.2.2 | `1e69f48acb82d1966a394da916b4c1698aa569d6` |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |

## Design

- `build`: after `uv build`, one step writes the SBOM to `sbom/ziran-${RELEASE_TAG}.cdx.json`
  and a second `upload-artifact` uploads it as `sbom`. The SBOM stays out of `dist/` so
  `gh-action-pypi-publish` never sees it.
- `attest`: needs `build`; two downloads, then `actions/attest` in provenance mode (subjects
  `dist/*` and the SBOM file) and in SBOM mode (subjects `dist/*`, `sbom-path` the file).
  CycloneDX is detected by `bomFormat`, `serialNumber` and `specVersion`, which uv writes.
- `publish-pypi`, `publish-testpypi`: `needs: [build, attest]`.
- `github-release`: downloads `sbom`; `files` lists `dist/*` and `sbom/*.cdx.json`.
- New actions are pinned by commit with the tag in a comment; existing tag pins stay (outside).

## Dry run

No step here can attest without a real release run: `actions/attest` needs the release job's
OIDC token. The PR proves the parts that can run before a tag:

- `actionlint` on `release.yml`;
- the contract test in CI;
- the exact `uv export` command on a `git archive` copy of the head.

The first tag after merge proves the rest: the `attest` job's summary lists both attestations,
and `gh attestation verify` on the PyPI wheel and on the release SBOM (spec scenario 4).

## Constitution Check

No source change in `ziran/`; strict mypy and the coverage gate unaffected; test first.

## Test plan

`tests/unit/test_release_workflow.py`: `attest` scopes and needs; no `run` step and only pinned
download and attest actions; the two attest modes and their subjects; both publish jobs need
`attest`; `build` exports CycloneDX 1.5 with the release arguments and uploads `sbom`;
`github-release` attaches it.

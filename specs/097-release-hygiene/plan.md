# Implementation Plan: release hygiene before the next tag

**Branch**: `fix/097-release-hygiene` | **Spec**: [spec.md](spec.md)

## Technical Context

GitHub Actions YAML and `pyproject.toml`; Python 3.11+ test (CI matrix 3.11, 3.12, 3.13) with
PyYAML, already a dependency. No new dependencies. Touched: `pyproject.toml`,
`.github/workflows/ci.yml`, `.github/workflows/release.yml`,
`tests/unit/test_release_workflow.py`.

Commits resolved on 2026-11-24 with `gh api repos/<repo>/commits/<ref> --jq .sha`, then checked
again against the tag written in the comment:

| Action | Ref before | Tag in comment | Commit |
|---|---|---|---|
| `actions/checkout` | v7 | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `astral-sh/setup-uv` | v7 | v7.6.0 | `37802adc94f370d6bfd71619e3f0bf239e1f3b78` |
| `actions/setup-python` | v7 | v7.1.0 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` |
| `actions/upload-artifact` | v7 | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/download-artifact` | v8 | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| `pypa/gh-action-pypi-publish` | release/v1 | v1.14.3 | `7245906fb61fa33a13554f9d5fb856fe61758086` |
| `softprops/action-gh-release` | v3 | v3.0.4 | `8a0cd651e5b2365bd640854a3fa5dfc70e4875f3` |

## Design

- `pyproject.toml`: one line, `<3` back to `<2`.
- `ci.yml` `lint`: a `uv lock --check` step before `uv sync --frozen`.
- `release.yml`: each tag or branch ref replaced by its commit, tag in a comment. The three
  `gh api` paths in `update-action-tag` are quoted for actionlint.
- Test: a line regex over the raw `release.yml` text (PyYAML drops comments), and a check that
  `ci.yml` `lint` runs `uv lock --check`.

# Implementation Plan: remove the React frontend and its build

**Branch**: `chore/084-remove-react-frontend` | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ bf85bba

## Summary

Delete `ui/`, `hatch_build.py`, its pyproject hook and `docker-compose.yml`. Cut the Node and
`ui/` steps from `ci.yml` and `release.yml`, the npm entry from Dependabot, the Web UI block
from `.gitignore`, the picomatch risk row and the `ZIRAN_DATABASE_URL` lines in `.env.example`.
Rewrite the Dockerfile as one Python stage that installs the CLI. A unit test reads the repo
files and holds the result.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13); GitHub Actions YAML; Docker.
**Primary Dependencies**: none new. The test uses stdlib `tomllib` and the existing PyYAML.
**Storage**: none. The Postgres service and its `pgdata` volume go with docker-compose.
**Testing**: `tests/unit/test_no_frontend_build.py`; `uv build` with Node off `PATH`;
`podman build` and `podman run <image> --help`; actionlint and `bash -n` on every run script.

## Constitution Check

- Hexagonal architecture: no Python source changes.
- Type safety: the test is annotated; mypy strict runs unchanged.
- Tests: test first, with `@pytest.mark.unit` on every test.
- Simplicity: deletions plus an eight-line Dockerfile.

## Code trace (develop @ bf85bba)

- `pyproject.toml` `[tool.hatch.build.hooks.custom]` points at `hatch_build.py`, which runs
  `npm ci && npm run build` in `ui/` when Node is on `PATH`.
- `Dockerfile` stage 1 is `node:20-slim`; stage 2 copies `ui/dist` into
  `ziran/interfaces/web/static/` and installs `.[ui]`, an extra #525 removed.
- The old Dockerfile copied neither `README.md`, `LICENSE`, `NOTICE` nor `.git`, which hatchling
  and hatch-vcs need. The new one copies the three files and passes the version through
  `SETUPTOOLS_SCM_PRETEND_VERSION`.
- `ci.yml`: `dependency-audit` ends with the npm audit step; `frontend-build` is all Node.
- `release.yml`: Node setup and `cd ui && npm ci && npm run build` before `uv build`.
- `test.yml`: `uv run playwright install chromium --with-deps` stays.

## Out of scope (other items)

- #523: README, docs, roadmap and specs, including `CLAUDE.md` and the
  `examples/21-promptfoo-integration` README (its `setup-node` is for promptfoo users, not the UI).

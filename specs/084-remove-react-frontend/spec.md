# Feature Specification: remove the React frontend and its build

**Feature Branch**: `chore/084-remove-react-frontend`
**Created**: 2026-11-18
**Status**: Active
**Plan item**: UI-521-FRONTEND (goal G-6), GitHub issue #521, part of #520.
**Base**: `develop` @ bf85bba (after #525 removed the web backend).

## The promise in our own words

The web UI leaves the open ziran package (#520). #525 removed its Python half. This item removes
the other half: the React app in `ui/` and everything that builds, ships or audits it. That is
the hatch build hook that runs `npm`, the Node stage and UI server in the Dockerfile, the
Postgres and UI services in `docker-compose.yml`, the Node steps in CI and release, the npm
Dependabot entry, the Web UI `.gitignore` block and the picomatch risk row that only applied to
`ui/`.

After it, the Docker image is a plain CLI image: `pip install .` with `ENTRYPOINT ["ziran"]`.
Building the wheel and sdist needs no Node.js, and no CI job runs in `ui/` or needs Node.

It keeps `test.yml`'s Playwright install, which serves the browser adapter, and
`ziran/interfaces/graph_style/`, which the HTML report reads. README and docs belong to #523.

This is a breaking change, announced by the #520 release note: the Docker image no longer serves
the UI, and `docker compose up` no longer exists.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The package builds without Node.js (Priority: P1)

1. **Given** the PR head, **When** `uv build` runs with no Node.js on `PATH`, **Then** it
   produces a wheel and sdist, and neither holds `ui/`, `hatch_build.py` or
   `ziran/interfaces/web/static/`.

### User Story 2 - The Docker image is a CLI (Priority: P1)

1. **Given** the PR head, **When** `docker build .` runs, **Then** it builds from one Python
   stage, and `docker run <image> --help` prints the ziran CLI help.

### User Story 3 - CI needs no Node.js (Priority: P1)

1. **Given** the workflows, **When** they are read, **Then** no step uses `actions/setup-node`,
   runs `npm` or works in `ui/`, and Dependabot has no npm entry.
2. **Given** `test.yml`, **When** it is read, **Then** it still installs Playwright chromium.

### Edge Cases

- `docker-compose.yml` holds only the `db` and `ziran-ui` services, so it is deleted whole.
- `.env.example` names `ZIRAN_DATABASE_URL` only for docker-compose; nothing in `ziran/` reads
  it after #525, so the commented line goes.

## Requirements *(mandatory)*

- **FR-001**: `ui/`, `hatch_build.py` and `[tool.hatch.build.hooks.custom]` MUST be deleted.
- **FR-002**: The Dockerfile MUST have one Python stage that runs `pip install .` and
  `ENTRYPOINT ["ziran"]`, with no `ZIRAN_DATABASE_URL`, no `libpq5`, no `EXPOSE` and no `ui`.
- **FR-003**: `docker-compose.yml` MUST be deleted.
- **FR-004**: `ci.yml` MUST lose the npm audit step and the `frontend-build` job; `release.yml`
  MUST lose the Node setup and frontend build steps.
- **FR-005**: `dependabot.yml` MUST lose the npm `/ui` entry.
- **FR-006**: `.gitignore` MUST lose the Web UI block; `docs/security/risk-acceptances.md` MUST
  lose the picomatch row; `.env.example` MUST lose the `ZIRAN_DATABASE_URL` lines.
- **FR-007**: `test.yml` MUST keep `playwright install chromium`.

## Success Criteria

- **SC-001**: `tests/unit/test_no_frontend_build.py` passes at the head and fails on `develop`.
- **SC-002**: `uv build` with Node off `PATH` succeeds; the wheel listing has no frontend asset.
- **SC-003**: `docker build .` and `docker run <image> --help` succeed (podman locally).
- **SC-004**: actionlint passes on the changed workflows.

## Assumptions

- The `frontend-build` job is deleted whole, not emptied: every step in it was Node or `ui/`.
  It is not a required check (the `main-protection` ruleset requires lint, typecheck and test
  only). Overturn: a ruleset requires `frontend-build`.
- The Dockerfile keeps `python:3.12-slim` and drops `libpq5` (it was for asyncpg, which left
  with the `ui` extra) and `EXPOSE 8484`. It copies `README.md` and `LICENSE`, which hatchling
  reads for the metadata, and `.git` is not needed because the image sets
  `SETUPTOOLS_SCM_PRETEND_VERSION` from a build arg. Overturn: the image must carry a real
  version without the build arg.
- The dependabot header comment about npm advisories stays: it is history of the security
  setting, not a live npm entry. Overturn: the owner wants it reworded under #523.

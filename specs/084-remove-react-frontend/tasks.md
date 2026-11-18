# Tasks: remove the React frontend and its build

Base: `origin/develop` @ bf85bba. Branch `chore/084-remove-react-frontend`. Test first: T001 runs
red before T002.

## Phase 1 - Test (US1, US2, US3)

- [x] T001 `tests/unit/test_no_frontend_build.py`: `ui/`, `hatch_build.py` and
      `docker-compose.yml` are gone and pyproject has no custom hook; no workflow step uses
      `setup-node`, runs `npm` or works in `ui/`; `test.yml` installs Playwright chromium;
      Dependabot has no npm entry; the Dockerfile is one Python stage with `ENTRYPOINT ["ziran"]`.

## Phase 2 - Remove

- [x] T002 Delete `ui/`, `hatch_build.py`, `docker-compose.yml` and the pyproject hook.
- [x] T003 Rewrite the Dockerfile as a CLI image.
- [x] T004 `ci.yml`: drop the npm audit step, its comment and the `frontend-build` job.
- [x] T005 `release.yml`: drop the Node setup and frontend build steps.
- [x] T006 `dependabot.yml`, `.gitignore`, `.env.example`, `docs/security/risk-acceptances.md`.

## Phase 3 - Gates

- [x] T007 `uv build` with Node off `PATH`; list the wheel and sdist and grep for frontend assets.
- [x] T008 `podman build` and `podman run <image> --help`.
- [x] T009 actionlint, YAML parse and `bash -n` on every run script.
- [x] T010 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv lock --check`; T001 under `timeout 120`. The full suite and coverage come from CI.
- [x] T011 Open the draft PR to `develop`.

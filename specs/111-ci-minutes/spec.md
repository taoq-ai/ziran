# Feature Specification: cut GitHub Actions minutes in the engine CI

**Feature Branch**: `ci/111-ci-minutes`
**Created**: 2026-11-26
**Status**: Active

## The promise in our own words

Every pull request runs the full Python matrix (3.11, 3.12, 3.13), lint, typecheck, the
dependency audit and the integration tests, even when it changes only Markdown. A new push to the
same pull request does not stop the older run, so superseded runs bill to the end.

After this change:

1. A pull request that touches only docs (`docs/` except `docs/guides/`, `specs/`, `.specify/`,
   `.claude/`, root-level `*.md`, `mkdocs.yml`, `LICENSE`) does no install and no test work, and
   the docs build runs on it. Shipped Markdown (prompts, plugin skills, test fixtures) and
   `docs/guides/` pages that tests execute count as code, as do root `SECURITY.md` (a test reads it)
   and any `.py`, `.pyi` or `.ipynb` file under a docs folder (lint runs over the whole tree). Lint, typecheck and the three test jobs
   still start and report success, because the `main-protection` ruleset (refs/heads/main) requires
   `lint`, `typecheck`, `test (3.11)`, `test (3.12)` and `test (3.13)`. `on.paths` is not used for
   them, and no job-level `if` guards a required matrix job: a skipped matrix job leaves its
   expanded check name unreported. The steps are gated instead.
2. The non-required jobs (`dependency-audit`, `integration-test`) are skipped on a docs-only pull
   request.
3. A new push to a pull request cancels the older run of the same workflow. Push and scheduled
   runs use a group of their own run id, so they never share a group and are never cancelled.
4. A PR that touches Python keeps all three matrix versions.

Dependency caching already exists: `astral-sh/setup-uv@v7` turns its cache on by default on
GitHub-hosted runners, keyed on `uv.lock`. No change.

## Acceptance scenarios

- A docs-only PR: `lint`, `typecheck` and `test (3.11|3.12|3.13)` report success in seconds;
  `dependency-audit` and `integration-test` are skipped.
- A PR with any other file: every job runs as before.
- Two pushes in a row to one PR: the first run is cancelled.
- A push to `develop`: every job runs, nothing is cancelled.

## Assumptions

- `.github/ci/classify.sh` fails closed: it says docs-only only when both API calls succeed, the
  list holds every changed file (fewer than 3000), and every path, a rename's old path included,
  is docs. Any error means code. It always exits 0, because a failed `changes` job would skip the
  required jobs and a skipped check passes. `.github/ci/test_classify.sh` runs in the job against
  a stub client.
- The docs build on a PR is a `build` job in `docs.yml` (`mkdocs build`, no deploy). Overturn by
  deleting that job.
- Push events always count as code. A docs-only push to `develop` is rare and the run is cheap to
  keep.
- CodeQL workflows are not touched.
- The `detection-accuracy` and `pentest-eval` jobs already skip their own work and keep their
  rules; only a concurrency group is added to them and to the other path-filtered workflows.

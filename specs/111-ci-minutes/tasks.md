# Tasks: cut GitHub Actions minutes in the engine CI

- [x] T001 Add the `changes` job and step gates to `.github/workflows/ci.yml` (lint, typecheck) and job gates (dependency-audit)
- [x] T002 Add the same to `.github/workflows/test.yml` (test matrix, integration-test)
- [x] T003 Add the PR-cancelling concurrency group to the eight PR workflows
- [x] T004 Validate with `actionlint` and measure recent docs-only and Python PRs

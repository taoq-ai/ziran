# Plan: cut GitHub Actions minutes in the engine CI

## Design

- `ci.yml` and `test.yml` each gain a `changes` job. On `pull_request` it lists the PR files
  (`gh api repos/$REPO/pulls/$PR/files --paginate`) and sets `code=false` only when every file
  matches the docs pattern. Other events set `code=true`.
- Required jobs (`lint`, `typecheck`, `test`) get `needs: changes` and
  `if: needs.changes.outputs.code == 'true'` on every step, so the job and its check name always
  report. The matrix keeps its names.
- Non-required jobs (`dependency-audit`, `integration-test`) get the same condition at job level.
- `grep` runs without `-q` so `gh` is not killed by SIGPIPE under `pipefail`.
- Every workflow that runs on `pull_request` (`ci`, `test`, `detection-accuracy`, `pentest-eval`,
  `benchmark`, `action-test`, `lint-ci-templates`, `policy-refresh-selftest`) gets
  `concurrency: group: workflow-ref, cancel-in-progress: only for pull_request`.
- No new third-party action. The uv cache is already on by default in `setup-uv@v7`.

## Measure (recent runs, billed minutes = each job rounded up to a whole minute)

| Case | Before | After |
|---|---|---|
| Docs-only PR (#560), without CodeQL | 9 jobs, 25 min | 8 jobs, about 8 min |
| Python PR (#568), without CodeQL | 12 jobs, 30 min | 13 jobs, about 31 min, plus one superseded run cancelled per extra push |

Method: `gh run list --commit <sha>`, then `gh run view <id> --json jobs`, rounding each job up
to a minute. The after figures are an estimate: the gated jobs run only checkout-free steps.

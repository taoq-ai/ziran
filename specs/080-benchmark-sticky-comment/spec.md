# Feature Specification: one sticky Benchmark Coverage comment per PR

**Feature Branch**: `ci/080-benchmark-sticky-comment`
**Created**: 2026-11-18
**Status**: Active
**Plan item**: G5-BENCH-STICKY (goal G-5).
**Base**: `develop` @ 3e7eb6b.
**Input**: the owner's complaint, "the benchmark on the PRs is not really getting updated".

## The promise in our own words

Today `.github/workflows/benchmark.yml` (Benchmark Coverage) runs `gh pr comment` on every push,
so a PR collects one new comment per push (PR #514 has four) and a reader sees the first, stale
one. Each body starts with a structlog line (`[info] attack_library_initialized ...`), because the
step captures stdout and ziran's unconfigured logger prints there. The comment step is skipped
when the regression check fails, so a regression never shows on the PR. And the job that runs
`uv sync` and the PR's code holds `pull-requests: write`.

After this change, using the shape of `detection-accuracy.yml` (spec 077, #509):

1. The benchmark job holds `contents: read` only. On a PR, `regression_check.py --comment PATH`
   writes the markdown comment to a file. The file starts with the marker
   `<!-- ziran-benchmark-coverage -->`, holds no log line, and is written also when the check
   finds a regression. The job uploads it as an artifact.
2. A separate comment job holds only `pull-requests: write`. It has no checkout and runs no
   repository code. It has a per-PR concurrency group, and its steps continue on error. It
   downloads the file, appends the head and base SHAs, and edits the `github-actions[bot]`
   comment whose body starts with the marker, or creates one.
3. A regression still fails the benchmark job, and its comment still posts with the regression
   list. A missing or failed comment (a fork or Dependabot token) never changes the benchmark
   job's result.

Out of scope: deleting old unmarked comments on open PRs, the library-wide stdout logging default
(G5-LIB-LOGGING), and what the comment reports.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A PR shows one current Benchmark Coverage comment (Priority: P1)

**Acceptance Scenarios**:

1. **Given** this PR (it touches `benchmarks/**`), **When** a second commit is pushed, **Then**
   the PR has exactly one `github-actions[bot]` comment that starts with the marker, it shows the
   second push's head SHA, and no new Benchmark Coverage comment appears.
2. **Given** that comment, **Then** its first line is the marker, it contains
   `## Benchmark Coverage Report`, and no line is a log line (a timestamp followed by `[info`,
   `[debug` or `[warning`).

### User Story 2 - A regression shows on the PR and still fails (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a change that drops a vector below the committed baseline, **When** the workflow
   runs, **Then** the benchmark job fails and the comment still posts with the regression list.
2. **Given** a token that cannot comment (a fork or Dependabot), **When** the comment job fails,
   **Then** the benchmark job's result is unchanged.

### User Story 3 - The write token never meets PR code (Priority: P1)

**Acceptance Scenarios**:

1. **Given** the workflow file at the head, **Then** the job that runs `uv sync` has no
   pull-requests permission, and the only job with `pull-requests: write` has no checkout and
   runs no repository code.

## Requirements *(mandatory)*

- **FR-001**: `benchmarks/regression_check.py --comment PATH` MUST write the markdown report to
  PATH, starting with the line `<!-- ziran-benchmark-coverage -->`, before it exits 1 on a
  regression.
- **FR-002**: The comment file MUST carry a note on what the Changes delta is relative to: the PR
  base when `--delta-baseline` is given, otherwise a warning that it fell back to
  `benchmarks/results/baseline.json`.
- **FR-003**: The check's stdout and stderr output MUST be unchanged; the comment never comes
  from captured stdout.
- **FR-004**: The workflow MUST hold `contents: read` at the top level; only the comment job adds
  `pull-requests: write`, and it has no checkout and no `uv`/`python` step.
- **FR-005**: The comment job MUST select the comment to edit with a jq filter that matches only
  `github-actions[bot]` comments whose body starts with the marker, and all `github.*` values in
  `run:` scripts MUST come through `env`.
- **FR-006**: The comment job MUST run with `if: always()` on PRs, a concurrency group per PR
  number, and `continue-on-error` on its steps.

## Success Criteria

- **SC-001**: After two pushes this PR has one marker comment, edited in place.
- **SC-002**: `tests/unit/test_benchmark_regression.py` asserts the marker, the absence of log
  lines, the regression case, the jq selector and the job permissions.

## Assumptions

- The existing `:x: **Regressions detected:**` line plus list is the failing banner; no second
  banner is added. Overturn if the owner wants a banner above the table.
- Old unmarked comments stay on open PRs (out of scope); the bot edits only the marker comment.
- The workflow's own file joins its path filter, so a workflow-only change runs it, as
  `detection-accuracy.yml` does for itself.

# Feature Specification: benchmark PR comment delta from the PR base branch

**Feature Branch**: `054-benchmark-pr-delta`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #327 (release 0.42.0, "faster scans, truer graphs" batch, pass 2).
**Base**: `develop` @ 7e1ef38.
**Siblings (parallel, separate worktrees)**: #451 / spec 053 (ENABLES edge fan-out, agent_scanner
+ knowledge_graph tests), #264 / spec 055 (ATLAS coverage docs + one assertion in
`tests/integration/test_atlas_coverage_script.py`). No shared file: this feature touches only
`benchmarks/regression_check.py`, `.github/workflows/benchmark.yml`,
`tests/unit/test_benchmark_regression.py` and `benchmarks/results/baseline.json`.
**Scope**: CI hygiene, option 2 of the issue. Lightweight spec.
**Input**: the "Benchmark Coverage Report" PR comment printed by
`benchmarks/regression_check.py --format markdown` computes its `**Changes:**` line against the
committed `benchmarks/results/baseline.json`, last refreshed 2026-03-20 (commit eb82578, PR #196:
445 vectors / 99 multi-turn). CI never refreshes it (by design: auto-refresh would defuse the
"no decrease" gate). Every PR therefore shows the cumulative drift since March, not its own
contribution. Measured on `develop` @ 7e1ef38 (`uv run python benchmarks/regression_check.py
--format markdown`): `**Changes:** **Vectors**: +216 | **Multi-turn**: +130` with no vector change
in the tree.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The PR comment shows only this PR's delta (Priority: P1)

A contributor opens a PR against `develop`. The Benchmark Coverage Report comment's `Changes:`
line reflects only the vectors / multi-turn vectors / harm categories that the PR itself adds,
relative to the PR base branch.

**Why this priority**: the issue's whole ask (acceptance bullet 1).

**Independent Test**: offline, `regression_check.main()` with stubbed current metrics, a
committed-baseline file and a separate delta-metrics file (US1.1-1.2). End to end, only a live
`pull_request` run of `.github/workflows/benchmark.yml` (US1.3).

**Acceptance Scenarios**:
1. **Given** committed baseline `total_vectors=445, multi_turn_vectors=99`, a delta-metrics file
   with `661 / 229` and current metrics `670 / 230` (all other gate keys equal), **When**
   `regression_check.py --format markdown --delta-baseline <file>` runs, **Then** the output
   contains `**Changes:** **Vectors**: +9 | **Multi-turn**: +1` and does not contain `+225`,
   and the process exits 0.
2. **Given** the same files and no `--delta-baseline`, **Then** the delta is computed against
   the committed baseline exactly as today (`**Vectors**: +225 | **Multi-turn**: +131`).
3. **Given** a `pull_request` event, **When** the workflow runs, **Then** it checks out
   `github.event.pull_request.base.sha` into a side directory, collects that tree's metrics with
   that tree's own `benchmarks/regression_check.py --update-baseline` importing that tree's
   `ziran` package, and passes the produced JSON as `--delta-baseline` to the PR-head markdown
   run; the posted comment ends with a note naming the base commit the delta is relative to.

### User Story 2 - The regression gate is unchanged (Priority: P1)

**Why this priority**: issue acceptance bullet 2; the scope brief keeps `baseline.json` as the
gate with unchanged semantics.

**Acceptance Scenarios**:
1. **Given** committed baseline `total_vectors=700`, a delta-metrics file with `600` and current
   metrics `670`, **When** `regression_check.py --format markdown --delta-baseline <file>` runs,
   **Then** the output contains `:x: **Regressions detected:**` and
   `Total attack vectors decreased: 700 -> 670`, and the process exits 1, even though the
   current value is above the delta-metrics value.
2. **Given** a `push` to `develop`/`main`, **Then** the workflow behaves exactly as today: no
   base checkout, no base collection, no comment; the "Run benchmark regression check" step is
   unchanged.

### User Story 3 - A failed base collection is visible, never silent (Priority: P1)

**Why this priority**: scope brief (c). The current comment step swallows failures (`|| true`);
a silent fallback would reintroduce the misleading cumulative delta without anyone noticing.

**Acceptance Scenarios**:
1. **Given** the base checkout or base metric collection step fails (e.g. the base tree cannot
   import with the PR's environment), **When** the comment is posted, **Then** the job does not
   fail on that step, the delta falls back to the committed `baseline.json`, and the comment
   ends with a warning line saying the base metrics could not be collected and the `Changes`
   line is relative to the committed `benchmarks/results/baseline.json`.
2. **Given** `--delta-baseline` points at a missing or non-JSON file, **When** the script runs,
   **Then** it exits with argparse's usage error (exit code 2) naming the path, instead of
   silently using the committed baseline.

### User Story 4 - Interim mitigation applied once (Priority: P2)

**Acceptance Scenarios**:
1. **Given** this PR, **Then** `benchmarks/results/baseline.json` is regenerated by
   `uv run python benchmarks/regression_check.py --update-baseline` (real output, not
   hand-edited), so the gate compares against current `develop` numbers.

### Edge Cases
- `pull_request.base.sha` is the base-branch tip when the event fired; the head checkout is the
  merge ref (head merged into that tip). The delta is therefore exactly the PR's contribution,
  even when `develop` moved after the branch point (better than the merge-base).
- No positive delta (e.g. a PR that changes no vectors, including this one): today's rule is kept
  - no `**Changes:**` line is printed. The footer note still states what the delta is relative
  to, so a zero delta is distinguishable from a missing comparison.
- Negative deltas are not shown in `Changes:` (unchanged; decreases versus the committed baseline
  appear under "Regressions detected"). Out of scope per the brief.
- `benchmarks/` is a namespace package (no `__init__.py`); with `PYTHONPATH=<base checkout>`, the
  base tree's `benchmarks.*` and `ziran` win over the head's (PYTHONPATH precedes the editable
  `_editable_impl_ziran.pth` entry). A module that exists only in the head tree would still
  resolve from the head portion of the namespace, but the base script only imports modules that
  exist in its own tree.
- The base script's `--update-baseline` writes to its own tree
  (`<base checkout>/benchmarks/results/baseline.json`, path derived from `__file__`); the head
  tree's `baseline.json` is never touched in CI.
- Fork PRs: the base checkout is of `base.sha` in this repository (trusted code, credentials not
  persisted). The comment post keeps its existing `|| true` (a fork's read-only token cannot
  comment; unchanged behaviour).
- Text format (`--format text`): the same flag drives its "Improvements:" delta line, for a
  consistent CLI; the gate is unaffected there too.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (CLI flag)**: `benchmarks/regression_check.py` gains one optional argument
  `--delta-baseline PATH` (metrics JSON in the `--update-baseline` shape). When given, the
  `Changes:` (markdown) and `Improvements:` (text) deltas are computed against it; when omitted,
  behaviour is byte-for-byte today's.
- **FR-002 (gate unchanged)**: regressions (the "Regressions detected" lines and the exit code 1)
  are always computed against the committed `benchmarks/results/baseline.json`, whether or not
  `--delta-baseline` is given. `_check_regressions` is not modified.
- **FR-003 (flag validation)**: an unreadable or non-JSON `--delta-baseline` path is a usage
  error (`parser.error`, exit 2) naming the path.
- **FR-004 (workflow, PR only)**: in `.github/workflows/benchmark.yml`, for `pull_request` events
  only: (a) check out `github.event.pull_request.base.sha` into `_bench_base/` with
  `actions/checkout@v7` (`ref` + `path`, `persist-credentials: false`); (b) run
  `uv run python _bench_base/benchmarks/regression_check.py --update-baseline` with
  `PYTHONPATH=${{ github.workspace }}/_bench_base`; (c) pass
  `--delta-baseline _bench_base/benchmarks/results/baseline.json` to the comment step's markdown
  run when (b) succeeded. Push runs are unchanged.
- **FR-005 (visible fallback)**: the base checkout and base collection steps use
  `continue-on-error: true`; the comment step branches on the collection step's `outcome` and
  appends exactly one footer line: on success a note naming the short base SHA, on failure a
  `:warning:` line stating the fallback to the committed baseline. The fallback is never silent.
- **FR-006 (baseline refresh)**: `benchmarks/results/baseline.json` is regenerated once with
  `uv run python benchmarks/regression_check.py --update-baseline`; no hand edits.
- **FR-007 (no regressions)**: existing tests in `tests/unit/test_benchmark_regression.py` pass
  unmodified; no new dependency; no change outside the four files above (plus this spec dir and
  the expected CLAUDE.md agent-context churn); `uv.lock` unchanged; `actionlint` clean on
  `benchmark.yml`.

### Assumptions (recorded, most conservative reading)
- **Option 2, not option 1**: the gate stays absolute against the committed baseline (brief);
  making the gate base-relative would change which PRs fail and is out of scope.
- **`base.sha`, not merge-base**: see Edge Cases; it is what the issue's intent ("relative to its
  base branch") means for a merge-ref run, and it needs no extra `git fetch --deepen`.
- **Base metrics come from the base tree's own code**: metrics are computed by
  `get_attack_library()` and the base tree's `benchmarks/` collectors, so swapping only the
  vectors directory would be wrong. The base script is invoked only with `--update-baseline`,
  which exists on `develop` today.
- **Zero delta keeps today's "no line" output**: no new markdown wording beyond the footer note.
- **Flag name `--delta-baseline`**: mirrors the existing `--update-baseline` vocabulary.

### Follow-ups (not in this feature; no issue created)
- Show negative per-PR deltas in the comment (e.g. a PR that removes vectors on purpose).
- Fold `--update-baseline` into the release checklist so the gate's reference does not drift.

### Key Entities
- **Metrics JSON**: the dict written by `--update-baseline` (`timestamp`, `total_vectors`,
  `categories`, `owasp_coverage_pct`, `owasp_covered`, `multi_turn_vectors`,
  `harm_category_count`, `tactics_count`, `benchmark_count`, `benchmark_details`). Unchanged shape.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1.1, US1.2, US2.1 and US3.2 pass as unit tests driving `regression_check.main()`
  with stubbed metrics and `tmp_path` files (no network, no LLM, no keys).
- **SC-002**: `uvx --from actionlint-py actionlint .github/workflows/benchmark.yml` exits 0.
- **SC-003**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-004 (live only)**: US1.3 / US3.1 (workflow wiring) can only be proven by a real
  `pull_request` run. The PR touches `benchmarks/**`, so `Benchmark Coverage` runs on it; the
  implementer quotes the posted comment's actual `Changes:` line (or its absence) and footer in
  the PR body. Expected for this PR (no vector changes): no `Changes:` line and the base-SHA
  footer. If the run cannot be observed, the criterion is reported as unverified.
- **SC-005**: the local proof of the base-import mechanism is recorded in plan.md (base tree
  imported its own `ziran`); it is a stand-in for SC-004, not a replacement.

# Tasks: external benchmark harness for the response detectors

Base: `develop` @ 8943b83. Test first: each test task ran red (collection failed on the missing
package, or the new assertion failed) before its implementation task.

## Phase 1 - Metrics (US4)

- [x] T001 `tests/unit/test_external_eval_metrics.py`: registered constants, Wilson values,
      undefined at n = 0, X1 to X4 numerators and denominators, deterministic cluster bootstrap.
- [x] T002 `benchmarks/external_eval/metrics.py`. T001 passes.

## Phase 2 - Intake (US2)

- [x] T003 `tests/unit/test_external_eval_intake.py`: unsafe member names, symlinks, each zip
      limit, manifest and section 1 hashes, unsafe or linked paths, licence, fields,
      JailbreakBench targets, `git check-ignore` of the download folder.
- [x] T004 `benchmarks/external_eval/intake.py`. T003 passes.

## Phase 3 - Mapping and the InjecAgent evaluator (US1)

- [x] T005 `tests/unit/test_external_eval_mapping.py`: one hand-made fixture per benchmark
      format, the post-injection cut, the `None`/`N/A` skip, `invalid` and `parse_error`
      exclusions, the `ngrams` replacement, dropped prints, and `collect` per benchmark.
- [x] T006 `benchmarks/external_eval/injecagent_eval.py`, `mapping.py`, `collect.py`. T005
      passes.

## Phase 4 - Isolation and the CLI (US1, US3)

- [x] T007 `tests/unit/test_external_eval_run.py`: `-I` required, `-O` refused, sockets
      blocked, environment scrub and allow-list, module check, AgentDojo end to end at two
      pins, InjecAgent `..` member reported not evaluated, path refusals.
- [x] T008 `benchmarks/external_eval/isolation.py`, `worker.py`, `run.py`; `.gitignore` line
      for `/downloads/external-eval/`. T007 passes.

## Phase 5 - Gates and probes (SC-002, SC-003)

- [x] T009 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run mypy --strict --explicit-package-bases benchmarks/external_eval`,
      `uv run pytest -m "not integration" --cov=ziran`.
- [x] T010 Practice run at `study-v0` (`b813e4f`) and `develop` (`8943b83`) on the AgentDojo
      fixture; `pipeline.py` sha256 equals protocol section 1 at both; defaults equal the
      section 4 table.
- [x] T011 Mutation probes on a `git archive` copy: each guarded check removed in turn is
      caught by a test.

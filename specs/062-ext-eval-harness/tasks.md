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
      pins, InjecAgent `..` member reported not evaluated, path refusals, malformed or duplicate
      pins, a second run into the same output refused.
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

## Phase 6 - Gate fix round 1 (arch, quality, security at 9e65607)

- [x] T012 Tests first: empty split and no analysed unit fail intake (InjecAgent with unexpected
      member names, HarmBench `{}` and all non-binary); damaged members (bad CRC, corrupt stream,
      encrypted flag, size mismatch) fail by index with the member name kept out; limits are
      inclusive; the `max_bytes` cap; malformed AgentDojo tool calls; the version cell; the
      `None` action skip, first-user rule, tool-only marker, cluster key and `tools[0]` target;
      all four defence folders; PRIMARY; the hash-all loop; predictor direction and the `hit`
      cut on a stand-in export; worker socket, process and end-of-run module checks; frozen
      guard; PINNED_FILES; partial clones; bootstrap predictor and row; pin differences; an
      end-to-end AgentDojo run with excluded and negative units; an InjecAgent end-to-end run.
- [x] T013 Code: `read_member` maps zip errors to intake failures, encrypted members refused,
      member names anchored to a safe set, empty split refused, tool calls validated, process
      and C-library events blocked in the worker, fd 1 redirected, every loaded module hashed,
      per-pin environment recorded, partial clones refused.
- [x] T014 [evaluator-diff.md](evaluator-diff.md): syntax-tree diff of the copy against the
      pinned source.

## Phase 7 - Gate fix round 2 (security, quality at 1398fc1)

- [x] T015 Tests first (10 failed on the previous code): bzip2, LZMA and Zstandard members
      refused; a real `git clone --filter=blob:none` refused and unable to fetch; hash values in
      the summary equal `git show <pin>:<path>` hashes and `git rev-parse`; manifest and rows
      hashes; worker environment allow-list and the scrub count end to end; fd 1 writes kept off
      the verdict stream; `ctypes.dlopen`, `os.exec` and `os.system` blocked; the harness
      process's network block; data and output path refusals in both repositories; the tar data
      filter; the exploratory boundary; `--expect-split` and `--expect-harness`.
- [x] T016 Code: compression-method allow-list, `GIT_NO_LAZY_FETCH=1` and the promisor check,
      the data-filter error mapped to a refusal, the two expect flags, one `installed_sha256`.

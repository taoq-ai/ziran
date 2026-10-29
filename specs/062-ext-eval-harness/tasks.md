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

## Phase 8 - Gate fix round 3 (security at a8056a0)

- [x] T017 Tests first (10 failed on the previous code): a central-directory offset one byte
      too large, a UTF-8-flagged invalid local name, extract version 25.5 and a UTF-8-flagged
      invalid central name each fail intake and end not evaluated (exit 3); a seeded
      3,000-case byte-mutation fuzz lets only intake errors out; `installed_sha256` against
      `importlib.metadata`; a non-prefix `--expect-harness` value; an unreadable git config.
- [x] T018 Code: `open_zip` and `read_member` map `ValueError` (and in `open_zip`,
      `NotImplementedError`) to intake failures; `require_full_clone` checks git's exit code.

## Phase 9 - Gate fix round 4 (security at d9d7108)

- [x] T019 Tests first (8 intake tests failed, and the run tests failed at import, on the
      previous code): a zip64 offset of 2^63; zip64 offsets and sizes at boundary values; a
      4,300-plus-digit integer, deep lists and deep objects in JSON; a CSV field past the bound;
      a seeded fuzz of zip64 fields (300 cases) and of mutated member payloads in a valid
      archive (1,500 cases); an injected exception in the collect phase reported with its type
      only; a worker killed past its timeout, directly and through the CLI.
- [x] T020 Code: the boundary catch in `run.py`, `OverflowError` in `read_member`,
      `(ValueError, RecursionError)` at both JSON sites, the CSV bound and `csv.Error`, and
      `--worker-timeout`.
- [x] T021 The full CI suite on 3.12 exposed one more escape: crewai replaces `warnings.warn`
      with a function that rejects the `skip_file_prefixes` keyword zipfile passes on an
      overlapped entry, so `zf.open` raised `TypeError`. A test patches `warnings.warn` the same
      way (red first); `read_member` now maps `TypeError` to an intake failure. The harness
      process never imports crewai, but the test suite does.

## Phase 10 - Gate fix round 5 (arch, security at b5350c8)

- [x] T022 Tests first (10 failed on the previous code): a worker that writes 200,000 bytes to
      stderr before reading a 300,000-byte input completes under a 120 s wall clock; a stand-in
      pin that stalls at import stops the run with exit 2 within 30 s and no summary; a two-pin
      run whose second pin stalls writes no summary and no rows; `--expect-harness` mismatches
      exit 2; `run_settings` and `worker_wall_seconds` in the summary; the `manifest` phase label.
- [x] T023 Code: temporary files for the worker's stdin, stdout and stderr; its own session and a
      process-group kill on timeout; no not-evaluated summary on a timeout; the output size
      limit; `--expect-harness` checked before intake as a refusal; run settings recorded.

## Phase 11 - Gate fix round 6 (security at ebd2f15)

- [x] T024 Tests first (10 failed on the previous code): Ctrl-C on the harness kills a stalled
      worker; a worker whose grandchild outlives a normal exit leaves no process; a timed-out
      worker's grandchild is killed with it; a stderr file past the cap is a refusal; nan, inf,
      zero, negative and non-numeric timeouts are refused, also through the CLI. Timing bounds
      take a load margin of 90 s; every stall in them lasts 120 s or more, so a real hang
      still fails.
- [x] T025 Code: the process-group kill on every exit from the wait, the `PermissionError` retry,
      the stderr cap, the byte-count read cap, the timeout validator.

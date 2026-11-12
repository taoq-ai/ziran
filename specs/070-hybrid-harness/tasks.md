# Tasks: the harness's hybrid row and routing-share rows

- [x] T001 Write `tests/unit/test_external_eval_hybrid.py` and run it red (14 failed).
- [x] T002 Map the judge's keys in `mapping.agentdojo_units` and pass them from `run._worker_unit`.
- [x] T003 Add `user_messages` and `final_answer` to the worker's `METADATA_KEYS`.
- [x] T004 Add the four hybrid flags to `run._args`, with their refusals.
- [x] T005 Run the trace judge in the worker and add `hybrid` and the routing rows.
- [x] T006 Add the names to `PREDICTORS`; fill `reply_outcome`; score per variant in `_metrics`.
- [x] T007 Count band, outcomes and mask changes per variant; a record run prints them only.
- [x] T008 Update the tests of the old mapping and key-list contract.
- [x] T009 Time `_assert_linear` with `process_time`, best of three, 12x early fail; run the
  quadratic mutants of the mask and the mail pattern red.
- [x] T010 Run ruff, ruff format --check, mypy and the suite.
- [x] T011 Fix round at 7ad520c: merge develop (#496, `--paper`); record path made absolute, not
  resolved (CWE-59), with link, harness-folder, name, missing-file and empty-model tests.
- [x] T012 Judge the task-known variants too; add `sent` per share and `no_reply` by cause and
  label to the counts; add the row key `no_reply_cause`.
- [x] T013 Tests for the eight gaps the quality gate named; run each mutant red.

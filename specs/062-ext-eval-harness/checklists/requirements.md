# Requirements checklist: external benchmark harness for the response detectors

- [x] Each promise part (a) to (g) has a requirement and a test (spec "The item in my own
      words"; tasks T001 to T008).
- [x] Both item acceptance scenarios are tests: `test_agentdojo_fixture_end_to_end` and
      `test_injecagent_zip_with_dotdot_is_not_evaluated` (plus
      `test_injecagent_member_with_dotdot_fails_intake`).
- [x] No benchmark artifact is downloaded and nothing runs against a benchmark item; fixtures
      are hand-made.
- [x] Only the InjecAgent evaluator source (code) was fetched, at its pin, and its sha256
      matched protocol section 1.
- [x] Outputs hold counts, hashes, ids, labels and verdicts only; a test checks that no fixture
      text reaches stdout, the rows or the summary.
- [x] No change under `ziran/`; no new dependency.
- [x] The protocol head built against (`cbf25bd`) is in the spec and in every summary.

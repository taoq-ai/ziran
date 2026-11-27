# Tasks: TAP session isolation

- [x] T001 Write `tests/unit/test_tap_session_isolation.py` (isolated, shared, branch goal, ancestor turns) and run it red
- [x] T002 Add `_Tree.isolated`, `_fresh` (reset, replay, prompt under the exclusive gate) and `_book` in `ziran/application/attacks/campaign.py`
- [x] T003 Judge goals per branch (`_branch`) in `_node`, and fill the caller's turns and replies with one branch in `_finish`
- [x] T004 Record `session: isolated | shared` in `evidence.campaign` for TAP
- [x] T005 Stop on the cap between replays; update the two merged campaign tests whose target-call counts change
- [x] T006 Take the shared session gate in every `TacticExecutor` run; add the concurrency test and run it red without the change
- [x] T007 Run the touched tests on 3.11, 3.12 and 3.13, ruff, ruff format and mypy strict

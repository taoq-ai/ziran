# Tasks: Generated PoCs check for the canaries the scan recorded

Base: `origin/develop` at 9dbec90. Branch `fix/poc-recorded-canaries`. Test first.

- [x] T001 Stub tests in `test_poc_target_protocol.py`: canary only in a tool call (both PoCs exit 0), fixed agent with a fresh canary (both exit 1), `_indicators` cases, tool-call fallback to exit 2; run red against the base generator: 7 failed, 33 passed.
- [x] T002 `_indicators` takes recorded canaries from the reply and tool-call arguments, and keeps matched indicators found there; the httpx Python PoC drops the tool-call success branch.
- [x] T003 Old-contract tests: the two no-indicator tests get a reply without a canary.
- [x] T004 Test for a matched indicator seen only in tool arguments; red against the base: 1 failed.
- [x] T005 Docs: `docs/reference/cli.md`.
- [x] T006 Touched tests green (`test_poc_target_protocol.py`, `test_poc_generator.py`); ruff, format and strict mypy clean.
- [x] T007 Mutants in a `git archive` copy under `timeout -s KILL 120`.

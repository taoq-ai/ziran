# Tasks: PoCs reproduce against OpenAI-protocol and custom-path HTTP targets

Base: `origin/develop`. Branch `fix/poc-target-protocol`. Test first.

- [x] T001 Stub-server tests in `test_poc_target_protocol.py` (OpenAI and REST stubs on 127.0.0.1: leak, fix, hostile prompt, handler-equal request, endpoint argument, exit 2, tool calls, unrecorded reply, other protocols), run red: 14 failed.
- [x] T002 `PoCGenerator(target=...)`, `_request`, `_indicators`; cURL and Python PoCs built from them; standalone httpx Python PoC; exit codes 0/1/2.
- [x] T003 Old-contract tests in `test_poc_generator.py` moved to the new exit codes and an httpx driver.
- [x] T004 Tests for `auto`, `HttpAgentAdapter.protocol`, `poc --target` and `_save_results`, run red: 4 failed.
- [x] T005 `HttpAgentAdapter.protocol`; `scan` passes the target with the detected protocol; `poc --target`; missing protocol blocks fall back to the handler defaults.
- [x] T006 Docs: `docs/reference/cli.md`, default run instructions.
- [x] T007 Touched tests green; ruff, format and strict mypy clean.
- [x] T008 Mutants in a `git archive` copy under `timeout -s KILL 120`: 29 of 30 killed; the survivor (scan dropping the detected protocol) got a scan wiring test and is now killed, 30 of 30.

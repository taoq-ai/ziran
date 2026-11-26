# Tasks: spec 123

- [x] T001 Fixture plugin (`tests/fixtures/claude_code/aibom_plugin`), vendored schema, `tests/unit/test_aibom.py`; run red
- [x] T002 `ziran/application/aibom.py` and `ClaudeCodeScan.mcp_sources`; run green
- [x] T003 `audit --aibom` and `analyze-traces --aibom`; CLI tests green
- [x] T004 Docs page, CLI reference rows, nav
- [x] T005 ruff check, ruff format --check, mypy strict; touched tests on 3.11, 3.12, 3.13
- [x] T006 Fix round 1: no `${VAR}` expansion in the static loader; package only from a runner shape; guard tests (affects dedup, one shadow agent, dangling dependsOn, URL fragment, `mcp__` prefix); `--aibom` input checked up front; docs, schema licence URL, NOTICE

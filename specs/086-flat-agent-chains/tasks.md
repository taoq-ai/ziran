# Tasks: `ziran scan` finds tool chains on flat agents

Base: `origin/develop` @ 3b0589a. Branch `fix/086-flat-agent-chains`. Test first: T001 to T004
run red before T005.

## Phase 1 - Tests (US1 to US3)

- [x] T001 `tests/unit/test_langgraph_adapter.py`: rename `test_flat_langchain_adapter_misses_it`
      to `test_flat_langchain_adapter_finds_it` and expect the direct chain; assert
      `exfil_graph` gets no co-resident edge.
- [x] T002 `tests/unit/test_langchain_crewai_adapters.py`: a CrewAI crew with the two tools on
      two agents yields the chain through `AgentScanner`.
- [x] T003 `tests/unit/test_http_adapter.py`: probe discovery and an MCP `tools/list` each yield
      the chain through `AgentScanner`.
- [x] T004 `tests/unit/application/test_structure_import.py`: a topology that links tools adds no
      co-resident edge, one with no state channel does, skills stay out; 15 flat tools through
      `ResultBuilder.build` finish fast with cycles skipped.

## Phase 2 - Fix (FR-001 to FR-006)

- [x] T005 `graph.py`: `add_co_resident_tools`, `has_co_resident_tools`.
- [x] T006 `claude_code_audit.py`: `agent_chains` uses the helper.
- [x] T007 `structure_import.py` and `scanner.py` (net zero lines).
- [x] T008 `result_builder.py`: skip cycles on co-resident graphs.
- [x] T009 `graph.py` `find_all_attack_paths` skips co-resident edges;
      `tests/unit/application/test_enables_links.py` counts chain findings apart.

## Phase 3 - Fix round 1 (gate findings)

- [x] T013 `chain_analyzer.py`: cycles default off on co-resident graphs (pentest
      `analyze_graph` hang); `result_builder.py` back to a bare `analyze()`; a test patches
      `_find_chain_cycles` to raise.
- [x] T014 `structure_import.py`: per-agent co-resident sets when the topology lists agents;
      handoff test (no cross-agent chain) and unlisted-tools test.
- [x] T015 Tests: a self-loop state channel links no two tools; the `co_resident` marker
      survives `export_state`/`import_state`; `capabilities` is required.

## Phase 4 - Gates

- [x] T010 `ziran audit` on the Claude Code fixtures at base and head: identical output.
- [x] T011 `uv run ruff check`, `uv run ruff format --check`, `uv run mypy ziran/`, the touched
      test files plus `test_scanner_size.py` under `timeout 120`; full suite and coverage in CI.
- [x] T012 Open the draft PR to `develop`.

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

## Phase 4 - Fix round 2 (gate findings)

- [x] T016 `structure_import.py`: `MAX_CO_RESIDENT_TOOLS` cap with one warning;
      `chain_analyzer.py`: betweenness cap on big co-resident graphs. Tests: cap warns and adds
      no edge, the cap counts all sets, exactly the cap still links, betweenness patched to
      raise, a 1,000-tool MCP scan stays bounded.
- [x] T017 Tests: a linking channel with no agents plus an unrelated tool adds no edge; a graph
      node with two tools linked by state adds no edge.

## Phase 5 - Rethought design (round 3)

Test first: T018 to T020 ran red (5 failed, each through the raising patch or a missing
attribute, in 7 s) before T021.

- [x] T018 `tests/unit/application/test_structure_import.py`: a `walker_guard` fixture patches
      `nx.has_path`, `nx.all_simple_paths`, `nx.descendants`, `nx.simple_cycles` and
      `nx.betweenness_centrality` to raise on a graph with a co-resident edge. One hand-built
      graph (two sets sharing a tool, a real state path, two agents) runs every walker under
      it. Scale tests: two 50-tool agents sharing one tool, and 100 flat tools, each built
      under one 5 s bound.
- [x] T019 Tests: a repeated discovery adds the edges and the warning once; an 801-tool graph
      with no co-resident edge still runs betweenness; the pair table equals `_match_pattern`
      for every pair.
- [x] T020 `tests/unit/test_http_adapter.py`: an MCP `tools/list` of 101 tools through
      `run_campaign` shows the warning in the result JSON, the Markdown report, the HTML
      report, `ziran ci` output and the step summary.
- [x] T021 `graph.py` `structure_view` and `warnings`; every walker in spec.md's list reads the
      view; `chain_analyzer.py` shares `_candidate_pairs` between the direct and indirect rules.
- [x] T022 `structure_import.py`, `result_builder.py`, `phase.py`, `reports.py`,
      `html_report.py`, `main.py`, `github_actions.py`: the warning from the cap to each output.
- [x] T023 spec.md: the design rule, the walker list and the new scenarios; plan.md.
- [x] T024 Mutants in a scratch copy (24, all killed), the gates' probes at head, the audit and
      ground-truth benchmark comparisons at base and head.

## Phase 6 - Gates

- [x] T010 `ziran audit` on the Claude Code fixtures at base and head: identical output.
- [x] T011 `uv run ruff check`, `uv run ruff format --check`, `uv run mypy ziran/`, the touched
      test files plus `test_scanner_size.py` under `timeout 120`; full suite and coverage in CI.
- [x] T012 Open the draft PR to `develop`.

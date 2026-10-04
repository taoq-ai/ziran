# Tasks: reduce the capabilities x vulnerabilities ENABLES edge fan-out

Base: `origin/develop` @ 7e1ef38. Work on branch `053-enables-edge-fanout`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys. New tests carry
`@pytest.mark.unit` and live in `tests/unit/application/test_enables_links.py`. Names, signature,
tier order and edge shape are exactly those in [plan.md §Public contract](plan.md#public-contract).
Existing tests MUST NOT be modified. Every number written in the PR body comes from a command run
in this branch.

## Phase 1 - Selection function (FR-001; US1.1-US1.4, US2)

- [x] T001 Failing tests, class `TestEnablingCapabilities`: helper `_graph(*caps)` adding
      `AgentCapability` nodes via `add_capability`; tests for match by name, match by id, two
      invoked tools (insertion order), malformed evidence (`{}`, `{"side_effects": None}`,
      `{"side_effects": {"tools_invoked": "x"}}`) and unknown tool names falling to tier 2,
      dangerous-only fallback, all-capabilities fallback, empty graph -> `[]`, non-capability
      nodes (`add_tool("send_email")`, `add_agent_node("send_email", ...)` style ids) never
      returned, and no duplicates when a capability matches by both id and name. Import
      `enabling_capabilities` from `ziran.application.agent_scanner.enables_links`. Run
      `uv run pytest tests/unit/application/test_enables_links.py -k EnablingCapabilities` and
      confirm it fails (module missing).
- [x] T002 Create `ziran/application/agent_scanner/enables_links.py` per plan §1 (one function,
      stdlib + `knowledge_graph.graph` imports only). T001 passes.

## Phase 2 - Wire into the scanner (FR-002, FR-003; US1.5, US4.2)

- [x] T003 Failing tests, class `TestScannerLinksImplicatedCapabilities`:
      - `test_update_graph_edge_shape`: `AgentScanner(adapter=MockAgentAdapter(...),
        attack_library=AttackLibrary())`, capabilities added to `scanner.graph`, vulnerability
        nodes added, then `scanner._update_graph_from_phase(PhaseResult(...artifacts={vid:
        {"evidence": {"side_effects": {"tools_invoked": ["send_email"]}}}}, ...))`; only
        `tool_send_email -> vid` is `enables`, its attributes include
        `phase == result.phase.value`, `vid -> phase_<phase>` is `discovered_in`.
      - `test_end_to_end_mock_scan` (US4.2): six capabilities (`search_database`*, `send_email`,
        `shell_execute`*, `get_weather`, `calculator`, `read_file`*; * = dangerous, ids
        `tool_<name>`), `MockAgentAdapter(responses=["Sure! I have access to tools."],
        capabilities=..., vulnerable=True)`, `run_campaign(phases=[ScanPhase.RECONNAISSANCE,
        ScanPhase.VULNERABILITY_DISCOVERY])`; assert at least one vulnerability, every `enables`
        source is `tool_shell_execute`, `enables` count == vulnerability-node count, every
        vulnerability is the last node of some `critical_paths` entry,
        `len(critical_paths) == vulns + 3`.
      Run and confirm failure (today: `enables == 6 * vulns`).
- [x] T004 Edit `AgentScanner._update_graph_from_phase` in
      `ziran/application/agent_scanner/scanner.py` per plan §2: import `enabling_capabilities`,
      replace the comment + loop with the `evidence = ...` line and the call, update the
      docstring. T003 passes; `tests/unit/application/test_scanner_size.py` passes;
      `git diff --numstat ziran/application/agent_scanner/scanner.py` shows deletions >=
      insertions.

## Phase 3 - Path preservation and fan-out proofs (FR-004, FR-005; US3, US4.1, kept class)

- [x] T005 Tests (expected to pass on first run after T004; they are the regression contract):
      - module-level `_legacy_link(graph, result)`: verbatim copy of the pre-053 loop (adds
        `DISCOVERED_IN` + `ENABLES` from every capability), docstring "captured from develop @
        7e1ef38";
      - `_representative(link)`: builds the spec.md representative graph (six capabilities,
        `sensitive_data` links for the dangerous ones exactly as
        `_discover_and_map_capabilities` adds them, `import_structure` with one agent and the
        `messages` channel written by `tool_read_inbox` and read by `tool_send_email`, four
        vulnerabilities `vuln_exfil`/`vuln_rce`/`vuln_pi`/`vuln_ghost` with the spec evidence,
        one composition finding via `add_chain_finding`), recording the phase with `link`;
      - class `TestAttackPathsPreserved`: US3.1 (subset + equality with the hard-coded
        `EXPECTED_PAIRS` filter from plan.md), US3.2 (endpoint sets equal), US3.3 (named paths
        present), US3.4 (non-`ENABLES` paths identical, composition finding reachable);
      - class `TestFanOut`: US4.1 (25 vs legacy 200, `25 < 200 / 4`) and the kept edge class
        (three benign capabilities, two vulnerabilities without tool calls: 6 == legacy 6).
      If any fails, fix the implementation, not the expectations, unless the spec is wrong; then
      update spec.md/plan.md first.

## Phase 4 - Semantics docs (FR-006)

- [x] T006 [P] `ziran/application/knowledge_graph/graph.py`: comment on `EdgeType.ENABLES` per
      plan §3 (no value change).
- [x] T007 [P] `docs/concepts/knowledge-graph.md`: correct the `enables` row per plan §4.

## Phase 5 - Gates (FR-007, SC-004)

- [x] T008 Run the unmodified regression set and record real output:
      `uv run pytest tests/unit/test_knowledge_graph.py tests/unit/test_html_report.py
      tests/unit/test_chain_analyzer.py tests/unit/test_graph_export_enrichment.py
      tests/unit/test_multi_agent.py tests/unit/test_reports.py tests/unit/test_scanner.py
      tests/unit/application/test_structure_import.py tests/unit/application/test_result_builder.py
      tests/unit/application/test_scanner_size.py`.
- [x] T009 Full gates: `uv run ruff check .`, `uv run ruff format --check .`,
      `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%). `git diff --stat` lists only
      the five files in plan §Project Structure (plus the spec dir and the expected CLAUDE.md
      agent-context churn); `uv.lock` unchanged.
- [x] T010 PR body (against `develop`, `perf(graph): ...`): the rule and its tiers, the measured
      before/after `ENABLES` and `critical_paths` counts from the US4.2 test scenario (run it and
      paste real numbers), the justified dropped-path class, the kept tier-3 class, the
      downstream count effects (policy `max_critical_paths`, CI gate message), and SC-005 as
      unverified offline.

## Dependencies
T001 -> T002 -> T003 -> T004 -> T005. T006/T007 are independent and can run any time after T002.
T008 -> T009 after all code tasks; T010 last.

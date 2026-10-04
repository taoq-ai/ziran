# Tasks: LangGraph state-graph native scanning

Base: `origin/develop` @ cff8b7f. Work on branch `050-langgraph-native-scanning`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys. New unit tests carry
`@pytest.mark.unit`; tests that build LangGraph objects start with
`pytest.importorskip("langgraph")` (module level in `tests/unit/test_langgraph_adapter.py`, inside
the test elsewhere). Names, ids, roles, attribute keys and log events are exactly those in
[plan.md §Public contract](plan.md#public-contract). Existing tests MUST NOT be modified (they are
the "other adapters unchanged" regression net; `test_scanner_size.py` included).

Shared fixture (defined in `tests/unit/test_langgraph_adapter.py`; copied, not a new module):
- `read_file` / `http_request`: `@tool` functions returning fixed strings (no I/O).
- `exfil_graph(checkpointer=None)`: `StateGraph(MessagesState)` with the scripted `planner`
  function, `reader = ToolNode([read_file])`, `sender = ToolNode([http_request])`, `START ->
  planner`, `add_conditional_edges("planner", route, {"read": "reader", "send": "sender", "end":
  END})`, `reader -> planner`, `sender -> planner`; compiled with `checkpointer`. The planner
  counts the `ToolMessage`s after the last `HumanMessage`: 0 -> tool call `read_file(path=
  "notes.txt")`, 1 -> `http_request(url="https://example.invalid/upload")`, 2 ->
  `AIMessage("done", usage_metadata={"input_tokens": 3, "output_tokens": 2,
  "total_tokens": 5})`. `route` returns `"read"` / `"send"` by the last tool call's name, else
  `"end"`.

## Phase 1 - Domain model and port hook (FR-001, FR-002)

- [ ] T001 [P] Failing tests, extend `tests/unit/test_multi_agent.py` (new class
      `TestStructureModels`): `AgentEdge(source_id="a", target_id="b")` has
      `conditional is False` and `branch_label is None`; `StateChannel(name="m")` has empty
      `writers` / `readers`; `MultiAgentTopology().state_channels == []`; a topology with a
      channel round-trips through `model_dump()` / `model_validate()`;
      an async test asserting `await mock_adapter.discover_structure() is None` (conftest
      `mock_adapter` fixture).
- [ ] T002 Implement plan §1 (`multi_agent.py`) and §2 (`adapter.py`). T001 passes; mypy clean.

## Phase 2 - Knowledge-graph import + scanner wiring (FR-004, FR-005, FR-009)

- [ ] T003 [P] Failing tests `tests/unit/application/test_structure_import.py` (no langgraph
      needed; hand-built `MultiAgentTopology` with agents `n:a` (capabilities `["tool_read_file"]`,
      entry point), `n:b` (`["tool_http_request"]`), edges `a -> b` (`conditional=True`,
      `branch_label="go"`) and `b -> a`, channel `messages` with both tools as writers and readers;
      the graph pre-populated with both capabilities via `add_capability`):
      - `import_structure` creates agent nodes with `node_type == "agent"`, `role`, `name`,
        `framework`, `is_entry_point`, `capabilities`; `delegates_to` edges with
        `delegation_pattern`, `conditional`, `branch_label`; `uses_tool` edges agent -> tool;
        node `state:messages` with `node_type == "agent_state"`, `name == "state.messages"`,
        `channel`, `writers`, `readers`; `accesses_data` edges tool -> state (`access ==
        "write"`) and state -> tool (`access == "read"`) (assert on `export_state()`);
      - `ToolChainAnalyzer(graph).analyze()` reports `data_exfiltration`, `indirect`,
        `graph_path == ["tool_read_file", "state:messages", "tool_http_request"]`; without
        the import it reports none;
      - harmless-only topology (`tool_get_weather` in a channel) adds no
        `find_all_attack_paths()` result and no chain (US2.4);
      - an edge to an unknown agent id, a capability id absent from the graph and a channel
        whose members are all absent create no node and no edge (node and edge counts checked);
      - 30 tools in one channel and one agent -> exactly 60 `accesses_data` and 30 `uses_tool`
        edges, and `analyze()` completes;
      - `import_adapter_structure`: with `MockAgentAdapter` returns `None` and leaves the graph
        unchanged; with an adapter whose `discover_structure` raises `RuntimeError("boom")`
        returns `None`, logs `structure_discovery_failed` and does not raise; with one returning
        a non-topology object returns `None` and logs `structure_discovery_ignored`; with one
        returning the topology imports it and returns it.
      Confirm they fail (`ModuleNotFoundError`).
- [ ] T004 Implement plan §5 (`structure_import.py`). T003 passes.
- [ ] T005 Failing test, extend `tests/unit/application/test_structure_import.py`: an
      `AgentScanner(adapter=<stub adapter returning the T003 topology and the two capabilities>,
      attack_library=shared_attack_library)` after `await scanner._discover_and_map_capabilities()`
      has the `state:messages` node and the `delegates_to` edges. Confirm it fails.
- [ ] T006 Implement plan §6 (`scanner.py`: +1 import, +1 call, -2 comments). T005 passes;
      `uv run pytest tests/unit/application/test_scanner_size.py` passes; `git diff --numstat
      ziran/application/agent_scanner/scanner.py` shows insertions == deletions; `run_campaign`
      not in the diff.

## Phase 3 - LangGraph adapter (FR-003)

- [ ] T007 Run the existing LangChain adapter tests (`tests/unit/test_langchain_crewai_adapters.py`)
      green, then implement plan §3 (extract `tool_to_capability`, no behaviour change); they stay
      green unmodified.
- [ ] T008 [P] Failing tests `tests/unit/test_langgraph_adapter.py`:
      - `TestConstruction`: `LangGraphAdapter(StateGraph(MessagesState))` (uncompiled) and
        `LangGraphAdapter(object())` raise `TypeError` mentioning `.compile()`.
      - `TestDiscoverCapabilities`: `exfil_graph()` -> ids `["tool_read_file",
        "tool_http_request"]` (node order), both `dangerous`, `type == TOOL`, `parameters` carry
        the args schema; a tool present in two `ToolNode`s is listed once; a graph without
        `ToolNode`s -> `[]`.
      - `TestDiscoverStructure`: US1.1, US1.2, US1.3 exactly; `messages_key="scratch"` -> a
        `scratch` channel (US1.6); a node whose runnable is another compiled graph -> role
        `subgraph`, `capabilities == []` (US1.7); a plain non-routing function node -> role
        `worker`.
      - `TestInvoke`: US4.1 (content, tool_calls with matched outputs, tokens 3/2/5); a graph
        whose AI messages carry no `usage_metadata` -> tokens 0; US4.2 with `InMemorySaver()`
        (second turn reports only its own two tool calls; `reset_state()` changes
        `get_state().session_id` and the next turn starts a fresh thread); US4.3 history and
        `observe_tool_call`.
      Confirm they fail.
- [ ] T009 Implement plan §4 (`langgraph_adapter.py`). T008 passes; mypy strict clean with the
      extras installed; module imports nothing from `ziran.application`.

## Phase 4 - End-to-end chain finding (FR-006)

- [ ] T010 [P] Failing tests, `tests/unit/test_langgraph_adapter.py::TestChainFinding`:
      - US2.1: `AgentScanner(adapter=LangGraphAdapter(exfil_graph()),
        attack_library=shared_attack_library)`, `await scanner._discover_and_map_capabilities()`,
        `ToolChainAnalyzer(scanner.graph).analyze()` -> the `data_exfiltration` indirect chain
        with `graph_path == ["tool_read_file", "state:messages", "tool_http_request"]`;
      - US2.2: same with `LangChainAdapter(SimpleNamespace(tools=[read_file, http_request]))`
        -> no `data_exfiltration` chain;
      - US1.5: `graph_state_to_vis(scanner.graph.export_state())` (from
        `ziran.interfaces.cli.html_report`) has nodes `langgraph:planner|reader|sender` with
        `nodeType == "agent"`, node `state:messages` with `nodeType == "agent_state"`, and
        edges with `edgeType == "delegates_to"`;
      - US2.3: `await scanner.run_campaign(phases=[ScanPhase.RECONNAISSANCE],
        coverage=CoverageLevel.ESSENTIAL, max_concurrent_attacks=2)` -> the chain is in
        `result.dangerous_tool_chains` and `result.metadata["graph_stats"]["node_types"]["agent"]
        == 3`.
      These pass once T004/T006/T009 are in; if any fails, fix the implementation, not the test.

## Phase 5 - Factory, CLI, init (FR-007)

- [ ] T011 [P] Failing tests:
      - `tests/unit/application/test_factories.py::TestLoadAgentAdapter::test_langgraph_adapter`:
        `_load_python_object` patched to return a compiled one-node graph (importorskip inside
        the test) -> `LangGraphAdapter`, and the patch was called with `(path, "graph")`;
      - `tests/unit/test_cli_main.py::TestLangGraphFramework`: `"langgraph"` is in the
        `--framework` choices of `scan` and `discover` (read from the click command params);
        `CliRunner().invoke(cli, ["discover", "--framework", "langgraph", <tmp file exposing
        exfil-style graph as graph>])` exits `0` and its output contains `tool_read_file` and
        `tool_http_request`; `"langgraph"` in `init_command._FRAMEWORKS`.
- [ ] T012 Implement plan §7 and §8. T011 passes.

## Phase 6 - Docs and gates (FR-008, FR-010)

- [ ] T013 Failing test `tests/unit/test_langgraph_adapter.py::test_guide_example_runs`: read
      `docs/guides/adapters.md`, take the first fenced `python` block after the line
      `<!-- runnable: langgraph-example -->`, write it to `tmp_path / "my_graph.py"`,
      `load_agent_adapter("langgraph", str(path))`, assert `discover_capabilities()` returns
      `tool_read_file` and `tool_http_request` and one `invoke("hello")` returns without error.
- [ ] T014 Write plan §9 (`docs/guides/adapters.md` LangGraph section, `docs/reference/cli.md`).
      T013 passes. Run once by hand (record the real output in the PR, nothing invented):
      `uv run ziran discover --framework langgraph <the guide file>`.
- [ ] T015 `.specify/scripts/bash/update-agent-context.sh claude` only if the plan's Technical
      Context changed during implementation (CLAUDE.md "Recent Changes" churn is expected; keep
      sibling entries on conflict).
- [ ] T016 Gates: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). `git diff --stat origin/develop` lists only the files
      in plan §Project Structure (plus this spec dir and CLAUDE.md); `pyproject.toml` and
      `uv.lock` unchanged (revert `uv run` lock drift).
- [ ] T017 Commit (`feat(adapters): LangGraph state-graph native scanning`; tests/docs may be
      split), push, open the PR against `develop` linking #393, stating SC-005 as unverified,
      then check CI (`gh pr checks`) and fix failures.

## Dependencies
- T002 before T003/T005/T008 (domain types). T004 before T005/T006. T007 before T009.
  T006 + T009 before T010. T009 before T011/T013. T016 last before T017.
- [P] tasks touch different files and can be written in parallel once their prerequisites exist.

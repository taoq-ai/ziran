# Tasks: cap the HTML report knowledge-graph payload and escape its inlined JSON

**Input**: [spec.md](spec.md), [plan.md](plan.md). Base: `develop` @ 7d4132e. No prerequisite
feature; no shared file with the parallel siblings (045, 046, 047).

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no browser. New test classes carry
`@pytest.mark.unit`; existing tests in `tests/unit/test_html_report.py` and
`tests/unit/test_reports.py` MUST NOT be modified (they are the "under-cap = unchanged" and
scrubber / path-highlight regression net). Names, constants, signatures and the notice text are
exactly those in [plan.md §Public contract](plan.md#public-contract).

Shared test helpers (in `tests/unit/test_html_report.py`, not a new module):
- `_synthetic_state(n_tools, n_vulns, n_phases) -> dict[str, Any]` per plan §Reference fixture
  (`(200, 500, 8)` -> 708 nodes / 5,699 edges; assert those two counts once so the fixture cannot
  drift silently).
- `_reference_campaign() -> tuple[dict[str, Any], dict[str, Any]]` returning `(result_data,
  final_state)` with 8 phase stops (stop `k` = `_synthetic_state(200, 500 * k // 8, k)`).
- `_blob(html, name) -> Any`: `json.loads(re.search(rf"^const {name} = (.*);$", html, re.M)[1])`.

## Phase 1 — Script-safe JSON (FR-007, US5) — security first

- [x] T001 Failing tests `TestScriptEscaping`:
      - `_script_json(["</script><b>x"])` contains no `<` and `json.loads` of it returns the input;
        `_script_json({"a": "<!--<script>"})` contains no `<!--`.
      - `build_html_report` with a final graph, a critical path and one phase snapshot (two
        snapshots, so the scrubber is active) all containing a node whose `id` and `name` are
        `</script><b>x`: `html.count("</script>") == 2`; `"</script><b>x" not in html`;
        `_blob(html, "rawNodes")` has a node with that `id` and `label`; `_blob(html,
        "criticalPaths")[0]` contains that id; `_blob(html, "phaseStates")` stops contain it.
      - a node named `<!--<script>`: the text between `const rawNodes =` and the closing
        `</script>` contains no `<!--`.
      Confirm they fail (`ImportError` on `_script_json`, then the assertions).
- [x] T002 Implement `_script_json` and use it for the four blob placeholders in
      `build_html_report` (plan §3, §4 last bullet). T001 passes; every existing test passes.

## Phase 2 — Cap function (FR-001, FR-002, US2)

- [x] T003 Failing tests `TestCapGraphState` (call `_cap_graph_state` directly; shrink caps with
      `monkeypatch.setattr(html_report, "_MAX_VIS_NODES", k)` / `"_MAX_VIS_EDGES"` where a small
      hand-built graph is clearer):
      - `test_under_cap_returns_input_unchanged`: `sample_graph_state` -> result `is` the input.
      - `test_caps_nodes_and_edges`: `_synthetic_state(200, 500, 8)` -> `len(nodes) <= 150`,
        `len(edges) <= 300`, every edge's `source`/`target` in the kept ids; input lists not mutated
        (lengths and first/last ids unchanged).
      - `test_keeps_critical_path_and_phase_nodes`: 20 paths over tools with index >= 100 and
        `low` vulns (would lose on rank) -> all their nodes kept; all 8 phase nodes kept; a 21st path
        passed in the list is the caller's job (the function keeps whatever paths it is given).
      - `test_keeps_critical_path_edges`: a path edge of type `enables` survives when
        `_MAX_VIS_EDGES` is patched below the number of attack edges.
      - `test_vulnerabilities_outrank_other_nodes`: with `info`-severity vulns and dangerous tools
        competing for 3 free slots, the vulns win.
      - `test_ranks_by_severity_then_dangerous_then_centrality_then_type`: hand-built
        non-vulnerability nodes differing in one attribute at a time; kept set and order match the
        key in plan §2 step 3; `"HIGH"` ranks as `high`; non-string severity ranks as unknown.
      - `test_rank_is_deterministic_without_centrality`: all centrality `0.0` (and absent) -> two
        calls return identical id lists, ties broken by input order.
      - `test_drops_dangling_edges_and_prefers_attack_edges`: above the node cap, edges with a
        dropped endpoint are gone; with `_MAX_VIS_EDGES` patched, `exploits` / `can_chain_to` /
        `leads_to` edges are kept before `enables` / `discovered_in`; output lists are in input
        order.
      - `test_always_kept_set_larger_than_cap`: `_MAX_VIS_NODES` patched to 2 with 3 path nodes ->
        exactly the 3 path nodes (plus phase nodes) are kept.
      Confirm they fail.
- [x] T004 Implement the plan §1 constants and `_cap_graph_state` (plan §2) in
      `ziran/interfaces/cli/html_report.py`; replace the two literal `20`s in `_build_paths_html`
      with `_MAX_RENDERED_PATHS` (plan §7). T003 passes; `TestBuildPathsHtml` unchanged and passing;
      `uv run mypy ziran/` clean.

## Phase 3 — Wire the cap into the report and the phase stops (FR-003..FR-005, US1, US3)

- [x] T005 Failing tests:
      - `TestPhaseStatesCap::test_each_stop_is_capped`: `_build_phase_states(result_data, paths)`
        on `_reference_campaign()` -> 8 stops, each with `<= 150` nodes and `<= 300` edges and keys
        exactly `{"label", "nodes", "edges"}`.
      - `TestPhaseStatesCap::test_stop_keeps_path_nodes`: path nodes present in a stop survive in
        that stop.
      - `TestBuildHtmlReportCap::test_rawnodes_and_rawedges_capped`: `_blob(html, "rawNodes")` /
        `"rawEdges"` within caps, every edge `from`/`to` in the node ids, the path nodes present.
      - `TestBuildHtmlReportCap::test_critical_paths_blob_truncated`: 25 paths ->
        `len(_blob(html, "criticalPaths")) == 20`, the sidebar still says `…and 5 more paths`
        and the "Attack Paths" metric shows 25.
      - `TestBuildHtmlReportCap::test_under_cap_vis_lists_unchanged`: for `sample_graph_state`,
        `_blob(html, "rawNodes") == graph_state_to_vis(sample_graph_state)["nodes"]` (and edges).
      Confirm they fail.
- [x] T006 Implement plan §4 (except the notice) and §5: `shown_paths`, cap before
      `graph_state_to_vis`, `_build_phase_states(result_data, paths=None)`, `criticalPaths` from
      `shown_paths`. T005 passes; the existing `test_phase_scrubber_*` tests pass unmodified.

## Phase 4 — Truncation notice and byte budget (FR-006, US1.2, US4)

- [x] T007 Failing tests:
      - `TestGraphNotice::test_notice_when_truncated`: on `_reference_campaign()`, the html
        contains `id="graphCapNotice"` and the exact text `Showing 150 of 708 nodes and K of 5,699
        edges (highest-risk first).` where `K = len(_blob(html, "rawEdges"))` (formatted with `,`).
      - `TestGraphNotice::test_no_notice_when_not_truncated`: `sample_graph_state` ->
        `graphCapNotice` not in html.
      - `_build_graph_notice_html(5, 5, 3, 3) == ""`; `(150, 708, 300, 5699)` returns the exact
        `<p class="muted" id="graphCapNotice">...</p>` string of plan §6.
      - `TestReportSize::test_reference_campaign_under_budget`: `len(html.encode()) <= 2_000_000`
        for `_reference_campaign()`.
      Confirm they fail (the size test may already pass after T006; that is expected, keep it as
      the regression guard and note it).
- [x] T008 Implement `_build_graph_notice_html` and the `{graph_notice_html}` placeholder (plan §6).
      T007 passes. Run the reference campaign once from a command and record the printed byte count
      for the PR body (do not estimate it).

## Phase 5 — Docs (FR-009)

- [x] T009 [P] `docs/concepts/knowledge-graph.md`: the one sentence of plan §8.
- [x] T010 [P] `docs/community/roadmap.md` line 188: tick #217, "graph pagination" -> "graph size
      cap".

## Phase 6 — Gates

- [x] T011 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). `git diff --stat` shows only the four files of plan
      §Project Structure; revert any `uv.lock` drift. Commit
      `perf(report): cap HTML report graph payload and escape inlined JSON` (no `!`, no
      `Co-Authored-By`). PR to `develop` linking #217: quote the T008 byte count, state SC-005
      (browser render time) as unverified, list the scanner `ENABLES` fan-out as a follow-up.

## Dependencies
T001 -> T002 -> T003 -> T004 -> T005 -> T006 -> T007 -> T008 -> T011. T009 / T010 any time after
T004 (they only quote the constants). Phases 1 and 2 are independent of each other in code, but
they share the test file and the module, so run them in order.

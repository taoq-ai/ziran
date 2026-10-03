# Implementation Plan: cap the HTML report knowledge-graph payload and escape its inlined JSON

**Branch**: `048-html-report-graph-cap` | **Date**: 2026-10-03 | **Spec**: [spec.md](spec.md)
**Issue**: #217 (release 0.41.0, batch "gates you can leave on") | **Base**: `develop` @ 7d4132e.
**Parallel siblings**: #447 / 045, #395 / 046, #399 / 047. No shared file: this feature edits only
`ziran/interfaces/cli/html_report.py`, `tests/unit/test_html_report.py`,
`docs/concepts/knowledge-graph.md` and `docs/community/roadmap.md`.

## Summary
Before converting to vis-network data, `build_html_report` and `_build_phase_states` pass every
graph state through one pure function, `_cap_graph_state`, that returns the input untouched when it
fits in 150 nodes / 300 edges and otherwise keeps (1) the nodes of the first 20 critical paths and
all phase nodes, (2) vulnerability nodes by severity, (3) the rest by severity, `dangerous`,
centrality and node type; then it keeps only edges between kept nodes, critical-path edges first,
attack edges next. The page's `criticalPaths` blob is cut to the same 20 paths (the only ones the
UI can highlight). A one-line notice says `Showing N of M nodes and K of L edges` when the final
graph was cut. All four inlined JSON blobs go through `_script_json`, which escapes `<` as
`<`, closing the `</script>` breakout.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: stdlib `json`; existing `ziran.interfaces.graph_style.spec`
(`load_graph_style().is_attack_edge`), existing `ziran.domain.entities.alerting.SEVERITY_RANK`.
No new dependency, `uv.lock` unchanged.
**Storage**: N/A (the report is a single self-contained HTML file, unchanged).
**Testing**: pytest. The existing file carries no markers; every new test class gets
`@pytest.mark.unit` (constitution III), existing classes are not touched. Synthetic `graph_state` dicts built in the test module; blobs extracted from
the HTML with `re.search(r"^const rawNodes = (.*);$", html, re.M)` and `json.loads`. No network,
no LLM, no browser.
**Target Platform**: `ziran scan` / `ReportGenerator.save_html` HTML output.
**Project Type**: single Python package.
**Performance Goals**: reference fixture report <= 2,000,000 bytes (today 12,438,481).
**Constraints**: mypy strict; line length 100; graphs within both caps render the same node/edge
lists as today; no JavaScript change in the template.
**Measured today** (`develop` @ 7d4132e, scratch script, see spec §Input): 108 / 599 -> 1,473,591
bytes; 708 / 5,699 -> 12,438,481 bytes; ~445 bytes per vis node, ~324 per vis edge; empty report
27,789 bytes. Scratch projection with a naive 150 / 300 slice on the 708 / 5,699 fixture:
1,059,721 bytes. Largest vis element after `_script_json` escaping in that fixture: node 600 bytes,
edge 356 bytes -> upper bound `9 * (150 * 600 + 300 * 356) + 27,789 = 1,798,989` bytes.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | All logic stays in the driving adapter `ziran/interfaces/cli/html_report.py`. It imports a domain constant (`SEVERITY_RANK`) and the interfaces-level style spec, both already allowed (interfaces -> domain, interfaces -> interfaces). No application or domain change. |
| II. Type safety | PASS | Every new function annotated; inputs/outputs stay `dict[str, Any]` exactly like the surrounding module (`export_state()` dicts are not modelled today, and modelling them is out of scope; FR-008). No new data structure that would need a Pydantic model: the ranking key is a tuple. |
| III. Tests | PASS | Test-first (tasks.md); unit tests for the cap function, the phase stops, the notice, the escaping and the byte budget; all existing tests unmodified. |
| IV. Async-first | N/A | Pure string building, no I/O added. |
| V. Extensibility | PASS | No port touched; the attack-edge set comes from the shared style spec, not a second list. |
| VI. Simplicity | PASS | One cap function reused for the final graph and every phase stop, one escaping helper, three constants, one placeholder. No config, no CLI flag, no JS change, no id-reference scheme for phase stops. Reuses `SEVERITY_RANK` and `is_attack_edge`. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #217 implementer. All names are module-private (leading underscore) except the two
existing public functions, whose signatures do not change.

### 1. Constants (`ziran/interfaces/cli/html_report.py`, after `_VIS_NETWORK_VERSION`)

```python
from ziran.domain.entities.alerting import SEVERITY_RANK

# Graph payload caps for the self-contained report (spec 048). Applied to the
# final graph and to every phase-timeline stop.
_MAX_VIS_NODES = 150
_MAX_VIS_EDGES = 300
# Only the first N critical paths are listed in the sidebar and highlightable.
_MAX_RENDERED_PATHS = 20
# str-keyed view of the domain ordering (low=0 .. critical=3); unknown -> -1.
# A comprehension, not dict(SEVERITY_RANK): mypy rejects the Literal-keyed dict
# as SupportsKeysAndGetItem[str, int] (checked with mypy --strict on 7d4132e).
_SEVERITY_RANK: dict[str, int] = {k: v for k, v in SEVERITY_RANK.items()}
# Tie-break order of node types (lower ranks first); unknown types after all of these.
_NODE_TYPE_ORDER: tuple[str, ...] = (
    "vulnerability", "phase", "tool", "capability", "data_source", "agent", "agent_state",
)
```

### 2. `_cap_graph_state` (new)

```python
def _cap_graph_state(
    graph_state: dict[str, Any], paths: list[list[str]]
) -> dict[str, Any]:
    """Bound a graph state to _MAX_VIS_NODES nodes and _MAX_VIS_EDGES edges (spec 048).

    Returns ``graph_state`` itself when both lists are within the caps. Otherwise
    returns ``{**graph_state, "nodes": kept_nodes, "edges": kept_edges}``; the
    input is never mutated.
    """
```

Algorithm (exact):
1. `nodes = graph_state.get("nodes", [])`, `edges = graph_state.get("edges", [])`. If
   `len(nodes) <= _MAX_VIS_NODES and len(edges) <= _MAX_VIS_EDGES`: `return graph_state`.
2. `path_ids = {n for p in paths for n in p}`; `path_pairs = {(p[i], p[i + 1]) for p in paths for i
   in range(len(p) - 1)}`.
3. Pinned = nodes (in input order) with `node["id"] in path_ids` or `node.get("node_type") ==
   "phase"`. Remaining nodes sorted by key
   `(node_type != "vulnerability", -sev, -int(bool(dangerous)), -centrality, type_rank, index)`
   where `sev = _SEVERITY_RANK.get(severity.lower(), -1)` if `severity` is a `str` else `-1`;
   `centrality = float(node.get("centrality") or 0.0)`; `type_rank =
   _NODE_TYPE_ORDER.index(t)` if known else `len(_NODE_TYPE_ORDER)`; `index` is the input position.
   `kept_nodes = pinned + ranked[: max(0, _MAX_VIS_NODES - len(pinned))]`, then re-sorted into input
   order (so vis ids / layout stay stable and small diffs stay readable).
4. `kept_ids = {n["id"] for n in kept_nodes}`; candidate edges = input edges with `source` and
   `target` both in `kept_ids`. Sort candidates (stable) by key
   `(0 if (source, target) in path_pairs else 1 if spec.is_attack_edge(edge_type) else 2, index)`
   with `spec = load_graph_style()`, `edge_type = edge.get("edge_type", "")`; take the first
   `_MAX_VIS_EDGES`; re-sort into input order.
5. Return `{**graph_state, "nodes": kept_nodes, "edges": kept_edges}`.

Edge ids stay `e{idx}` assigned by `graph_state_to_vis` over the capped list (unchanged function).

### 3. `_script_json` (new)

```python
def _script_json(value: Any) -> str:
    """Serialize ``value`` for inlining inside a ``<script>`` element (spec 048).

    ``json.dumps`` leaves ``<`` as-is, so ``</script>`` or ``<!--`` inside a node
    name would end or corrupt the script element. ``\\u003c`` is the same character
    to JSON and JS.
    """
    return json.dumps(value).replace("<", "\\u003c")
```

### 4. `build_html_report` (signature unchanged)

```python
def build_html_report(
    result_data: dict[str, Any],
    graph_state: dict[str, Any],
    critical_paths: list[list[str]] | None = None,
) -> str:
```
Changes, in order:
- `paths = critical_paths or result_data.get("critical_paths", [])` (unchanged);
  `shown_paths = paths[:_MAX_RENDERED_PATHS]`.
- `capped = _cap_graph_state(graph_state, shown_paths)`; `vis_data = graph_state_to_vis(capped)`
  (replaces `graph_state_to_vis(graph_state)`).
- `phase_states = _build_phase_states(result_data, shown_paths)`.
- `graph_notice_html = _build_graph_notice_html(...)` (§6).
- Template kwargs: `graph_notice_html=graph_notice_html`, and
  `vis_nodes_json=_script_json(vis_data["nodes"])`,
  `vis_edges_json=_script_json(vis_data["edges"])`,
  `critical_paths_json=_script_json(shown_paths)`,
  `phase_states_json=_script_json(phase_states)`.
- `num_paths=len(paths)` and `paths_html=_build_paths_html(paths)` keep the full list (sidebar
  count and "...and N more paths" line unchanged).

### 5. `_build_phase_states` (extended, backward compatible)

```python
def _build_phase_states(
    result_data: dict[str, Any], paths: list[list[str]] | None = None
) -> list[dict[str, Any]]:
```
Each snapshot: `vis = graph_state_to_vis(_cap_graph_state(snapshot, paths or []))`. Skip rule and
stop shape `{"label": str, "nodes": [...], "edges": [...]}` unchanged. The existing one-argument
call in `test_phase_scrubber_absent_for_legacy_runs` keeps working.

### 6. Truncation notice

```python
def _build_graph_notice_html(
    shown_nodes: int, total_nodes: int, shown_edges: int, total_edges: int
) -> str:
    """Return the 'showing N of M' notice, or "" when nothing was cut (spec 048)."""
```
Called with `len(vis_data["nodes"]), len(graph_state.get("nodes", [])), len(vis_data["edges"]),
len(graph_state.get("edges", []))`. Returns `""` when `shown_nodes == total_nodes and shown_edges
== total_edges`, else exactly:

```html
<p class="muted" id="graphCapNotice">Showing {shown_nodes:,} of {total_nodes:,} nodes and {shown_edges:,} of {total_edges:,} edges (highest-risk first).</p>
```
Template: in the "Knowledge Graph" section, `{graph_notice_html}` on its own line between the
closing `</div>` of the metric grid and `{legend_html}`. The existing `.muted` class styles it; no
CSS change.

### 7. `_build_paths_html`
The two literal `20`s become `_MAX_RENDERED_PATHS`; output unchanged.

### 8. Docs
- `docs/concepts/knowledge-graph.md`, §Visualization, after the first paragraph: one sentence:
  "To stay fast on large campaigns the HTML report embeds at most 150 nodes and 300 edges per view
  (critical-path, phase and vulnerability nodes first, then by severity, dangerous flag and
  centrality) and shows a 'Showing N of M' note when it trims; the web UI always loads the full
  graph."
- `docs/community/roadmap.md` line 188: `- [ ]` -> `- [x]` and "graph pagination" -> "graph size
  cap" (issue link kept).
- No CHANGELOG edit (release-please).

### Reference fixture (tests)
`_synthetic_state(n_tools: int, n_vulns: int, n_phases: int) -> dict[str, Any]` in
`tests/unit/test_html_report.py`, same construction as the spec author's scratch script: `n_phases`
phase nodes; `n_tools` tool nodes (`dangerous` every 7th, `centrality 0.0`, 80-char description);
`n_vulns` vulnerability nodes (severity cycling critical/high/medium/low, `centrality 0.0`); per
vuln one `discovered_in` edge to its phase and `enables` edges from every `n_tools // 10`-th tool;
a `can_chain_to` chain over the tools. `(200, 500, 8)` -> 708 nodes / 5,699 edges. The campaign has
8 phase stops, stop `k` built with `n_vulns * k // 8`, and `critical_paths = [["tool_3", "tool_4",
"vuln_499"]]` plus one 20-path list for US2.1 (paths over tools with index >= 100 and low-severity
vulns so they would lose on rank alone).

## Acceptance criteria -> offline proof

| Criterion (issue as narrowed by the scope brief) | Proven by (all `tests/unit/test_html_report.py`) | Live? |
|---|---|---|
| Visualized graph capped by module constants | `TestCapGraphState::test_caps_nodes_and_edges` on `_synthetic_state(200, 500, 8)`: `len <= _MAX_VIS_*`; every edge endpoint kept | No |
| Ranking: severity, dangerous, centrality, type; not centrality alone | `test_ranks_by_severity_then_dangerous_then_centrality_then_type`: hand-built nodes, cap patched down with `monkeypatch.setattr(html_report, "_MAX_VIS_NODES", k)`; `test_rank_is_deterministic_without_centrality` (all `0.0`) | No |
| Critical-path, vulnerability, phase nodes always kept | `test_keeps_critical_path_and_phase_nodes` (20 paths over otherwise lowest-ranked nodes, all 8 phases); `test_vulnerabilities_outrank_other_nodes` | No |
| Edges with removed endpoints dropped, attack edges first | `test_drops_dangling_edges_and_prefers_attack_edges` (patched `_MAX_VIS_EDGES`); `test_keeps_critical_path_edges` (an `enables` edge on a path survives over attack edges) | No |
| Under-cap graph unchanged | `test_under_cap_returns_input_unchanged` (`is` identity) and the existing `TestGraphStateToVis` / `TestBuildHtmlReport` suites unmodified | No |
| Phase-state payload bounded | `TestPhaseStatesCap::test_each_stop_is_capped` (8 stops above caps); `test_stop_keeps_path_nodes`; existing scrubber tests unmodified | No |
| Byte budget | `TestReportSize::test_reference_campaign_under_budget`: `len(html.encode()) <= 2_000_000` on the reference campaign; the PR quotes the measured value printed by a command actually run | No |
| "Showing N of M" notice | `TestGraphNotice`: exact text with thousands separators on the reference campaign; absent (`graphCapNotice` not in html) on `sample_graph_state` | No |
| `</script>` breakout escaped in all four blobs | `TestScriptEscaping`: node `id`/`name` `</script><b>x` in final graph, path and phase stop -> `html.count("</script>") == 2`, `"</script><b>x" not in html`, `"<!--" ` absent from the data script for a `<!--<script>` name, `json.loads` of each `const ... = ...;` line round-trips; `_script_json` unit test | No |
| Existing phase-scrubber and highlightPath tests pass | Unmodified `test_phase_scrubber_*`, `TestBuildPathsHtml`, `test_includes_*` | No |
| Browser render speed | Not measurable offline (no headless browser); byte budget is the proxy (spec SC-005) | Unverified |

## Project Structure

### Documentation (this feature)
```text
specs/048-html-report-graph-cap/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/interfaces/cli/html_report.py   # edit: constants, _cap_graph_state, _script_json,
                                      #       _build_graph_notice_html, build_html_report,
                                      #       _build_phase_states(paths=), _build_paths_html constant,
                                      #       template placeholder {graph_notice_html}
tests/unit/test_html_report.py        # extend: TestCapGraphState, TestPhaseStatesCap, TestGraphNotice,
                                      #         TestScriptEscaping, TestReportSize, _synthetic_state
docs/concepts/knowledge-graph.md      # edit: one sentence
docs/community/roadmap.md             # edit: tick #217
```
**Structure Decision**: everything in the one adapter module; no new module (three small private
functions next to the code they serve).

## Release note for the implementer
Commit as `perf(report): cap HTML report graph payload and escape inlined JSON` (tests may be split
as `test(report): ...`; the escaping is part of the same change, `fix` wording in the PR body). No
`!`, no `BREAKING CHANGE` (output is a subset for large graphs only; no API change), no
`Co-Authored-By`. PR targets `develop`, links #217, quotes the reference-campaign byte count from an
actual run, and lists the scanner `ENABLES` fan-out as a follow-up (spec §Out of scope).

## Phases
- P1 (tests first): `_script_json` + wiring into the four blobs (FR-007). Security first: it is
  independent of the cap and smallest.
- P2 (tests first): constants, `_cap_graph_state` (FR-001, FR-002).
- P3 (tests first): wire into `build_html_report`, `_build_phase_states`, paths blob (FR-003..005).
- P4 (tests first): notice (FR-006); byte-budget test.
- P5: docs (FR-009).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.

## Complexity Tracking
None.

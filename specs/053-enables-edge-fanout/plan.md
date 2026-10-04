# Implementation Plan: reduce the capabilities x vulnerabilities ENABLES edge fan-out

**Branch**: `053-enables-edge-fanout` | **Date**: 2026-10-04 | **Spec**: [spec.md](spec.md)
**Issue**: #451 (release 0.42.0) | **Base**: `develop` @ 7e1ef38
**Parallel siblings**: #327 / spec 054 (`benchmarks/regression_check.py`, benchmark workflow),
#264 / spec 055 (ATLAS docs). Neither touches `agent_scanner/`, `knowledge_graph/` or
`docs/concepts/knowledge-graph.md`. No shared-file coordination needed.

## Summary
Replace the inner "every capability" loop of `AgentScanner._update_graph_from_phase` with a call
to a new pure function, `enabling_capabilities(graph, evidence)`, in a new sub-module
`ziran/application/agent_scanner/enables_links.py`. It returns the capability node ids to link to
one vulnerability: the capabilities the successful attack invoked
(`evidence["side_effects"]["tools_invoked"]`, matched on node id or capability name), else the
dangerous capabilities, else all capabilities (today's behaviour, kept for findings with no tool
evidence on agents with no dangerous tool). Edge type, direction and attributes are unchanged.
`EdgeType.ENABLES` gets a one-line semantics comment and the docs edge table row is corrected.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: existing NetworkX-backed `AttackKnowledgeGraph`; stdlib only
(`collections.abc.Mapping`, `typing.Any`). No new dependencies.
**Storage**: N/A (in-memory graph).
**Testing**: pytest `@pytest.mark.unit`; in-memory `AttackKnowledgeGraph`; `import_structure`
(spec 050) for the agent/state topology; `MockAgentAdapter` from `tests/conftest.py` for the
end-to-end scan; `AgentScanner(adapter=..., attack_library=AttackLibrary())`. No network, LLM or
keys.
**Project Type**: single Python package.
**Performance Goals**: `ENABLES` edges per vulnerability drop from `N` (capabilities) to the
number of implicated capabilities (typically 1-2); selection is `O(N)` per vulnerability, same as
today's loop.
**Constraints**: mypy strict; line length 100; `scanner.py` at its 750-line cap (diff net-zero or
negative); new sub-module < 400 lines (`test_scanner_size.py`); hexagonal layering (application
module importing only application `knowledge_graph` and stdlib).

## Design decision: evidence source
`evidence["side_effects"]["tools_invoked"]` rather than re-parsing `evidence["tool_calls"]`.
Both success paths (`AttackExecutor.execute`, `TacticExecutor`) already compute it from
`response.tool_calls` with `get_side_effect_summary`, which handles the `tool` / `name` /
`function.name` shapes. Re-parsing would duplicate `SideEffectDetector._extract_tool_name` (a
private helper). Malformed or missing data (not a dict, not a list, non-string items) falls
through to the fallback tiers; it never raises.

## Design decision: three-tier fallback
Tier 2 (dangerous capabilities) mirrors the existing `dangerous -> sensitive_data` link: those are
the tools that give a compromised agent impact. Tier 3 (all capabilities) exists only because
without it a finding with no tool evidence on an all-benign agent becomes unreachable (the
concrete example in spec.md "Kept edge class"); the issue requires that such a path is kept, not
lost. No "vector targets capability" tier: `AttackVector` has no such field (spec follow-up).

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | New module in `application/agent_scanner/`, imports `application.knowledge_graph.graph` (same layer) and stdlib only. No domain, infrastructure or interface change. |
| II. Type safety | PASS | Fully annotated pure function, `Mapping[str, Any]` input (evidence is an untyped dict today), `list[str]` output; mypy strict. No new data structures, so no new Pydantic model. |
| III. Tests | PASS | Test-first: unit tests for every tier, the path-regression test against a captured legacy linker, the edge-count test and an end-to-end `MockAgentAdapter` scan. Existing tests unmodified. |
| IV. Async-first | PASS | No I/O; pure synchronous graph read, called from the existing sync `_update_graph_from_phase`. |
| V. Extensibility | PASS | Knowledge graph stays the single source of truth; no port change. |
| VI. Simplicity | PASS | One ~25-line function, no class, no config knob, no new edge attribute. Shrinks `scanner.py`. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #451 implementer. Names, signature, tier order and edge shape MUST NOT change
without updating this file.

### 1. New module `ziran/application/agent_scanner/enables_links.py`

```python
"""Pick the capabilities an ENABLES edge links to a vulnerability (spec 053)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.application.knowledge_graph.graph import NodeType

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph


def enabling_capabilities(graph: AttackKnowledgeGraph, evidence: Mapping[str, Any]) -> list[str]:
    """Capability node ids implicated in a vulnerability whose attack produced *evidence*.

    First non-empty tier wins:
    1. capabilities whose node id or name is in ``evidence["side_effects"]["tools_invoked"]``;
    2. every dangerous capability;
    3. every capability (pre-053 behaviour: keeps a finding with no tool evidence reachable).
    """
```

Behaviour (normative):
- Candidates: `graph.get_nodes_by_type(NodeType.CAPABILITY)` only, in graph insertion order; the
  returned list preserves that order and has no duplicates.
- Invoked names: `side_effects = evidence.get("side_effects")`; if it is a dict and
  `side_effects.get("tools_invoked")` is a list, the set of its `str` items; otherwise empty.
- Tier 1 match: `node_id in invoked or node_data.get("data", {}).get("name") in invoked`
  (`data` is `AgentCapability.model_dump()`, set by `add_capability`). Guard `data` not being a
  dict.
- Tier 2: `node_data.get("dangerous", False)` truthy.
- Tier 3: all candidates. No capabilities -> `[]`.
- Pure: never mutates the graph, never raises on malformed evidence.

### 2. `ziran/application/agent_scanner/scanner.py` - `AgentScanner._update_graph_from_phase`

Signature unchanged: `def _update_graph_from_phase(self, result: PhaseResult) -> None`. The
4-line comment and the `for cap_id, _cap_data in self.graph.get_nodes_by_type(...)` loop become:

```python
            evidence = result.artifacts.get(vuln_id, {}).get("evidence", {})
            for cap_id in enabling_capabilities(self.graph, evidence):
                self.graph.add_edge(cap_id, vuln_id, EdgeType.ENABLES, {"phase": result.phase.value})
```

(wrap to 100 columns as ruff format dictates). Add
`from ziran.application.agent_scanner.enables_links import enabling_capabilities` next to the
other `agent_scanner` imports. Docstring: "links each vulnerability from the capabilities
implicated in it (see ``enables_links``) so that ``find_all_attack_paths`` ...". `NodeType` stays
imported (used for `NodeType.PHASE`). Net line delta <= 0; file stays <= 750 lines.
`result.artifacts[vuln_id]` is the dict `PhaseExecutor` writes (`name`, `category`, `severity`,
`evidence`); `.get` keeps a missing artifact on the fallback path.

### 3. `ziran/application/knowledge_graph/graph.py` - `EdgeType`

Comment only, no value change:

```python
    ENABLES = "enables"  # capability -> vulnerability it is implicated in (spec 053 tiers)
```

and, directly above it or in the class docstring, one line naming the tiers: invoked by the
successful attack, else dangerous capabilities, else all capabilities.

### 4. `docs/concepts/knowledge-graph.md` - Edge Types table

Row `enables`: replace "One capability enables another" with
"Capability implicated in a vulnerability: a tool the successful attack invoked; if none is
known, the dangerous capabilities; if there are none, every capability".

No CLI flag, config key, Pydantic field, edge attribute, node type or output-shape change.
`CampaignResult.critical_paths` keeps its type (`list[list[str]]`); only its length shrinks.

## How each acceptance criterion is proven offline

All in `tests/unit/application/test_enables_links.py` (`@pytest.mark.unit`).

| Criterion | Proof |
|---|---|
| US1.1 match by name | Graph with `tool_send_email` (`name="send_email"`) and others; `enabling_capabilities(g, {"side_effects": {"tools_invoked": ["send_email"]}}) == ["tool_send_email"]`. |
| US1.1 match by id | Capability `id="send_email"`, `name="Send mail"`; invoked `["send_email"]` -> `["send_email"]`. |
| US1.2 several tools | Invoked names of two capabilities -> both, in insertion order. |
| US1.3 malformed / unknown | Evidence `{}`, `{"side_effects": None}`, `{"side_effects": {"tools_invoked": "x"}}`, invoked `["delete_everything"]` -> equal to the tier-2 result. |
| US1.4 capabilities only | An `add_tool("send_email")` node and an `AGENT` node with matching ids are never returned. |
| US1.5 edge shape | Call `AgentScanner._update_graph_from_phase` (scanner built with `MockAgentAdapter`, `AttackLibrary()`, graph pre-populated) with a `PhaseResult`; every `enables` edge has `phase == result.phase.value`; a `discovered_in` edge per vuln still exists. |
| US2.1 dangerous fallback | No tool evidence, two dangerous of four -> exactly the two dangerous ids. |
| US2.2 all fallback | No tool evidence, no dangerous -> all ids. |
| US2.3 no capabilities | Empty graph -> `[]`. |
| US2.4 order | Result order equals insertion order of capabilities. |
| US3.1 path set | Representative graph (spec.md fixtures) built twice: legacy linker (test-local copy of today's loop) vs `_update_graph_from_phase`. Assert `set(after) <= set(before)` and `set(after) == {p for p in before if p[-1] not in vulns or (p[-2], p[-1]) in EXPECTED_PAIRS}` where `EXPECTED_PAIRS` is hard-coded: `(tool_send_email, vuln_exfil)`, `(tool_shell_execute, vuln_rce)`, `(tool_shell_execute, vuln_pi)`, `(tool_read_file, vuln_pi)`, `(tool_shell_execute, vuln_ghost)`, `(tool_read_file, vuln_ghost)`. Paths compared as tuples. |
| US3.2 endpoints | `{p[-1] for p in before} == {p[-1] for p in after}`. |
| US3.3 named paths | Membership asserts for the paths listed in spec.md US3.3. |
| US3.4 non-ENABLES paths | `[p for p in before if p[-1] not in vulns] == [p for p in after if p[-1] not in vulns]` (the `sensitive_data` paths), plus a composition finding added with `add_chain_finding` reachable identically before and after. |
| US4.1 edge count | 10 capabilities (2 dangerous), 20 vulnerabilities (15 with one invoked capability, 5 without): count edges with `edge_type == "enables"` == 25; legacy linker on the same graph == 200; `25 < 200 / 4`. |
| US4.2 end-to-end | `AgentScanner(MockAgentAdapter(vulnerable=True, capabilities=<six caps>))`, `run_campaign(phases=[RECONNAISSANCE, VULNERABILITY_DISCOVERY])`: all `enables` sources are `tool_shell_execute`; count == number of `vulnerability` nodes; every vulnerability ends some `critical_paths` entry; `len(critical_paths) == vulns + 3`. |
| Kept edge class | Only benign capabilities (3), two vulnerabilities without tool calls: `enables` count == 6 == legacy. |
| FR-002 size | `tests/unit/application/test_scanner_size.py` unmodified and passing; `git diff --stat` shows `scanner.py` with deletions >= insertions. |
| FR-007 regressions | Unmodified: `tests/unit/test_knowledge_graph.py`, `test_html_report.py`, `test_chain_analyzer.py`, `test_graph_export_enrichment.py`, `test_multi_agent.py`, `test_reports.py`, `test_scanner.py`, `tests/unit/application/test_structure_import.py`, `test_result_builder.py` (270 passed on `develop` @ 7e1ef38 before any change), then the full gate run. |
| SC-005 real graphs | Unverified offline; stated in the PR. |

## Project Structure

### Documentation (this feature)
```text
specs/053-enables-edge-fanout/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (files touched)
```text
ziran/application/agent_scanner/enables_links.py   # new: enabling_capabilities()
ziran/application/agent_scanner/scanner.py         # _update_graph_from_phase: loop -> call
ziran/application/knowledge_graph/graph.py         # EdgeType.ENABLES semantics comment
docs/concepts/knowledge-graph.md                   # enables row corrected
tests/unit/application/test_enables_links.py       # new: tiers, path regression, edge counts
```

`ziran/application/agent_scanner/__init__.py` is not changed (the function is internal to the
scanner, like `import_adapter_structure`).

## Complexity Tracking
None.

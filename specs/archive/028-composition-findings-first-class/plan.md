# Implementation Plan: Tool-composition chains as first-class findings

## Technical context
- Python 3.11+ (CI 3.11/3.12/3.13); Pydantic v2, NetworkX, existing `ToolChainAnalyzer`,
  `AttackKnowledgeGraph`, `ResultBuilder`, CI gate. No new dependencies.

## Design
1. **Graph** (`ziran/application/knowledge_graph/graph.py`): `add_chain_finding(chain) -> str`
   creates a `VULNERABILITY` node (`severity=chain.risk_level`, `category="tool_composition"`,
   `finding_source="composition"`, carrying type/description/remediation/chain_type/risk_score/tools)
   and `EXPLOITS` edges from each in-graph tool to the node. Reuses `add_vulnerability`/`add_edge`.
   `VULNERABILITY` already renders red and `EXPLOITS` dark-red dashed (`graph_style.json`); the new
   tool→vuln edges make the chain appear in `find_all_attack_paths` (so report highlight works).
2. **Result aggregation** (`ziran/application/agent_scanner/result_builder.py`): register each
   dangerous chain on the graph, then recompute `critical_paths`; `success` also true when a
   critical chain exists; add `metadata["finding_sources"]` + `composition_finding_count`.
3. **CI gate** (`ziran/application/cicd/gate.py`): `_count_findings` adds `dangerous_tool_chains`
   by `risk_level`. Default thresholds (`max_critical_findings: 0`) then fail on a critical chain.
4. **Scan summary** (`ziran/interfaces/cli/main.py`): headline reflects composition findings.
5. **Reports**: unchanged markdown/JSON section; HTML graph shows the red node automatically.

## Phases
- P1: graph API + unit tests.
- P2: result builder + success/metadata + tests.
- P3: CI gate counting + tests.
- P4: CLI summary + report verification + borderline benchmark + regression.
- Gate: ruff, ruff format, mypy strict, pytest --cov ≥ 85%.

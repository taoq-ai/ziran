# Tasks: Tool-composition chains as first-class findings

- [x] T001 `AttackKnowledgeGraph.add_chain_finding(chain)` — synthesize a `tool_composition`
      VULNERABILITY node + `EXPLOITS` edges to the chain tools (`ziran/application/knowledge_graph/graph.py`).
- [x] T002 `ResultBuilder.build()` — register every dangerous chain on the graph before path
      enumeration; `success` includes critical chains; add `composition_finding_count` +
      `finding_sources` to metadata (`ziran/application/agent_scanner/result_builder.py`).
- [x] T003 CI gate — `_count_findings` counts `dangerous_tool_chains` by severity, so a critical
      composition fails the default gate (`ziran/application/cicd/gate.py`).
- [x] T004 Scan summary — add an explicit "Critical Compositions" row (`ziran/interfaces/cli/main.py`).
- [x] T005 Tests — composition → `success=True` + red VULNERABILITY node + reachable path
      (`tests/unit/application/test_result_builder.py`); gate fails on a critical chain and counts
      alongside detector findings (`tests/unit/test_cicd.py`); benign composition is NOT flagged
      (precision); spec-027 benchmarks stay green.
- [x] T006 Gates — ruff, ruff format, mypy strict, pytest --cov (≥ 80% fail-under; suite green).

Note: composition findings are graph-based, so they are not a detection-accuracy benchmark row
(that dataset targets the response-based IndicatorDetector). Precision is pinned by spec-027's
benchmark (unchanged) + the `test_benign_composition_is_not_flagged` unit test.

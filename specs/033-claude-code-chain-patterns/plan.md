# Implementation Plan: Tool-chain patterns for Claude Code built-in and MCP tool names

**Branch**: `033-claude-code-chain-patterns` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)
**Issue**: #417 | **Consumed by**: #421 (trace path reuses the same alias module)

## Summary
Add one pure alias module that maps Claude Code tool names to the capability keywords the existing
chain patterns already use, call it from the two places `ToolChainAnalyzer` derives a tool's
matching form, add five `claude_code` patterns plus a single-tool `unrestricted_execution` finding
for bare `Bash`, and add a safe/vulnerable Claude Code pair to the ground-truth benchmark.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: stdlib `re`; existing PyYAML (pattern loading), Pydantic v2 (`DangerousChain`), NetworkX. No new dependencies.
**Storage**: N/A — patterns in `ziran/application/knowledge_graph/chain_patterns.yaml`; benchmark YAML under `benchmarks/ground_truth/`.
**Testing**: pytest (`@pytest.mark.unit`), no network, no LLM.
**Target Platform**: library + CLI (unchanged)
**Project Type**: single Python package (`ziran/`)
**Performance Goals**: resolution is O(1) dict lookup + one regex per tool id per analysis; negligible.
**Constraints**: mypy strict; line length 100; existing matching behaviour for non-Claude-Code ids unchanged.
**Scale/Scope**: 1 new module (~50 lines), 3 edited source files, 1 YAML, 4 benchmark YAML, 1 doc.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | `tool_aliases.py` lives in `application/knowledge_graph/`, imports only stdlib. Consumers: `application/knowledge_graph/chain_analyzer.py` and (via the analyzer, or directly) `application/trace_analysis/`. Infrastructure MUST NOT import it. The Cedar fix is inside the existing infrastructure adapter. |
| II. Type safety | PASS | Fully annotated; module constants typed (`dict[str, str]`, `frozenset[str]`, `re.Pattern[str]`). `DangerousChain` (Pydantic) reused for the single-tool finding. |
| III. Tests | PASS | Unit tests first for the alias module, analyzer, Cedar guard and trace reuse. Benchmark data verified with `validate.py` / `run.py`. |
| IV. Async-first | N/A | No I/O added. |
| V. Extensibility | PASS | New chains are YAML patterns, not code. Only the single-tool finding is code, because the YAML schema is pair-only and one finding does not justify a schema change. |
| VI. Simplicity | PASS | One function + one constant; no class, no registry, no config knob. Reuses existing keywords and vulnerability types wherever they fit. |

No violations; Complexity Tracking not needed.

## Design

### 1. `ziran/application/knowledge_graph/tool_aliases.py` (new — the single alias map)
```python
_BUILTIN_ALIASES: dict[str, str] = {
    "Read": "read_file", "Grep": "read_file", "Glob": "read_file",
    "Write": "write_file", "Edit": "write_file", "NotebookEdit": "write_file",
    "Bash": "shell_execute", "WebFetch": "http_request", "WebSearch": "browse_url",
    "Agent": "spawn_subagent",
}
UNRESTRICTED_EXEC_TOOLS: frozenset[str] = frozenset({"Bash", "Bash(*)"})
_OUTBOUND_VERBS = frozenset({"send", "post", "create", "reply", "publish", "update"})
_RULE = re.compile(r"(\w+)\((.*)\)", re.DOTALL)          # Claude Code "Name(specifier)"
_SECRET_PATH = re.compile(r"...", re.IGNORECASE)          # FR-004 list
_GIT_PUSH = re.compile(r"\bgit\s+push\b")

def canonical_tool_name(tool_id: str) -> str: ...
```
Resolution order in `canonical_tool_name`:
1. `tool_id.startswith("mcp__")`: `parts = tool_id.split("__", 2)`; if 3 parts, split server and
   tool on `[_-]+` (lower-cased), take the first tool token not in the server tokens; if it is in
   `_OUTBOUND_VERBS` return `"send_email"`. Otherwise return `tool_id` unchanged.
2. `m = _RULE.fullmatch(tool_id)` → `name, spec = m[1], m[2]` else `name, spec = tool_id, ""`.
3. `canonical = _BUILTIN_ALIASES.get(name)`; `None` → return `tool_id` unchanged.
4. `canonical == "read_file"` and `_SECRET_PATH.search(spec)` → `"read_secret_file"`.
5. `name == "Bash"` and `_GIT_PUSH.search(spec)` → `"git_push"`.
6. return `canonical`.

Module docstring states it is the one shared Claude Code vocabulary for chain analysis and trace
analysis (#421) and must not be duplicated.

### 2. `ziran/application/knowledge_graph/chain_analyzer.py`
- `import` `canonical_tool_name`, `UNRESTRICTED_EXEC_TOOLS` from `tool_aliases`.
- `_match_pattern`: compute `source = canonical_tool_name(source_id)`, `target = canonical_tool_name(target_id)`
  and derive `source_lower/target_lower/source_kw/target_kw` from those. Cache key stays `(source_id, target_id)`.
- `_find_indirect_chains`: `tool_lower` and `tool_kw` built from `canonical_tool_name(tid)`.
- New `_find_unrestricted_execution(tool_nodes) -> list[DangerousChain]`: one finding per node id in
  `UNRESTRICTED_EXEC_TOOLS` (FR-007). Description/remediation as two module constants in the analyzer
  (e.g. "Unscoped shell access: the agent can read any file, reach the network and run arbitrary
  code with a single tool" / "Scope Bash with permission rules such as Bash(npm test:*) or deny it;
  run the agent in a sandbox"). `analyze()` extends `chains` with it before dedupe/scoring.
- Nothing else changes: node ids, `tools`, `graph_path` keep original names.

### 3. `ziran/application/knowledge_graph/chain_patterns.yaml`
- Add `claude_code` to the category list in the header comment.
- Insert a `# ── Claude Code ──` section as the FIRST entries under `patterns:` (first match wins;
  `read_secret_file` also keyword-matches the generic `read_file` patterns, so the specific pattern
  must precede them). Five entries per FR-006, each with `category: claude_code`, description and
  remediation. Vulnerability types reuse existing names (`delegation_to_rce`,
  `cross_agent_exfiltration`, `cross_agent_persist`, `code_exfiltration`) except the new
  `secret_file_exfiltration`.
- Verified on `develop` that `read_file + git_push` and `spawn_subagent + {shell_execute,
  http_request, write_file}` currently produce no direct match, so these patterns are additive.

### 4. `ziran/infrastructure/policy_renderers/cedar_renderer.py`
- `if len(tools) > 2:` → `if len(tools) != 2:`; skip reason covers both cases
  (e.g. "Cedar policy generation supports exactly two-tool sequences"). The other renderers already
  handle one tool (they iterate `tools`).

### 5. Benchmark ground truth (`benchmarks/ground_truth/`)
- `agents/vulnerable_claude_code.yaml`: `framework: claude_code`; tools `Read` (low), `WebFetch`
  (high), `Bash` (critical), `mcp__slack__slack_send_message` (high); no guardrails;
  `known_vulnerabilities` referencing OWASP LLM06/LLM08 design risk.
- `agents/safe_claude_code.yaml`: tools `Read`, `Grep`, `Glob` (all low); guardrails
  `no_shell_access`, `no_network_access`; `known_vulnerabilities: []`.
- `scenarios/tool_chain/tp_011_claude_code_read_webfetch_exfil.yaml`: `agent_ref:
  vulnerable_claude_code`, `source.type: design_risk`, expected chain `[Read, WebFetch]`,
  `risk_level: critical`, `chain_type: data_exfiltration`.
- `scenarios/tool_chain/tn_009_safe_claude_code_readonly.yaml`: `agent_ref: safe_claude_code`,
  `label: true_negative`, `expected_chains: []`.
- `README.md`: update totals (agents, scenarios, TP/TN) and the `tool_chain/` line (20: 11 TP, 9 TN).
- Do not commit `benchmarks/results/ground_truth_latest.md` churn produced by `run.py`.
- Note: `vulnerable_*` agents with OWASP refs become pentest-eval targets in full mode only; the
  CI regression gate uses `SUBSET_IDS` and is unaffected.

### 6. Docs — `docs/concepts/tool-chains.md`
New `## Claude Code tool names` section: alias table, MCP outbound rule, `Name(specifier)` form
(`Bash(git push:*)`, `Read(./.env)`), the unrestricted-`Bash` single-tool finding, and a note that
`analyze-traces` inherits the same vocabulary.

## Contract for #421 (trace path)
- Import only `canonical_tool_name` / `UNRESTRICTED_EXEC_TOOLS` from
  `ziran.application.knowledge_graph.tool_aliases`, and only from application-layer code. Do not copy
  the map.
- `AnalyzerService._analyze_session` already runs `ToolChainAnalyzer`, so `Read` then `WebFetch`
  matches with no trace-path change (SC-004 test guards this).
- Never put raw call arguments (Bash command, file paths) into graph node ids: node ids surface in
  `DangerousChain.tools`, reports and alerts unredacted. If #421 wants argument-aware resolution
  (`.env` read, `git push`), call `canonical_tool_name(f"{name}({arg})")` for matching only.
- A session using `Bash` (with >= 2 calls) will carry a `high` `unrestricted_execution` finding;
  it is not critical, so it does not trip a critical-only exit code.

## Project Structure
```text
ziran/application/knowledge_graph/tool_aliases.py        # new
ziran/application/knowledge_graph/chain_analyzer.py      # edit
ziran/application/knowledge_graph/chain_patterns.yaml    # edit
ziran/infrastructure/policy_renderers/cedar_renderer.py  # edit (1 line + reason)
tests/unit/test_tool_aliases.py                          # new
tests/unit/test_chain_analyzer.py                        # add tests
tests/unit/test_cedar_renderer.py                        # add test
tests/unit/test_analyzer_service.py                      # add test
benchmarks/ground_truth/agents/{vulnerable,safe}_claude_code.yaml
benchmarks/ground_truth/scenarios/tool_chain/{tp_011,tn_009}_*.yaml
benchmarks/ground_truth/README.md
docs/concepts/tool-chains.md
```

## Phases
- P1: alias module + unit tests (FR-001..FR-004).
- P2: analyzer wiring + YAML patterns + analyzer acceptance tests (FR-005, FR-006).
- P3: single-tool finding + Cedar guard (FR-007, FR-008).
- P4: benchmark data + docs (FR-009, FR-010).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%), `uv run python benchmarks/ground_truth/validate.py`,
  `uv run python benchmarks/ground_truth/run.py` (SC-003 numbers).

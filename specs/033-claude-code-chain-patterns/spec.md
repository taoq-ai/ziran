# Feature Specification: Tool-chain patterns for Claude Code built-in and MCP tool names

**Feature Branch**: `033-claude-code-chain-patterns`
**Created**: 2026-09-29
**Status**: Active
**Issue**: #417 (part of #415; prerequisite for #421)
**Input**: `ToolChainAnalyzer._match_pattern` keyword-matches tool ids against the patterns in
`chain_patterns.yaml`. Claude Code tool names (`Read`, `Grep`, `Glob`, `Write`, `Edit`,
`NotebookEdit`, `Bash`, `WebFetch`, `WebSearch`, `Agent`, `mcp__<server>__<tool>`) share none of
the keywords those patterns expect (`read_file`, `http_request`, ...), so real dangerous chains in
Claude Code agents are missed. Verified on `develop`: a graph of `Read`, `WebFetch`, `Bash`,
`Grep`, `Glob`, `Agent`, `mcp__slack__slack_send_message` (all pairs connected) yields zero chains.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Claude Code built-in names are recognised (Priority: P1)
A security engineer scans a Claude Code agent whose tool list is `[Read, WebFetch]`. ZIRAN reports
a critical data-exfiltration chain, exactly as it would for `[read_file, http_request]`.

**Why this priority**: This is the gap in the issue and the prerequisite for #421 (trace path).

**Independent Test**: Build an `AttackKnowledgeGraph` with the tools and CAN_CHAIN_TO edges, run
`ToolChainAnalyzer.analyze()`, assert on the returned `DangerousChain` list.

**Acceptance Scenarios**:
1. **Given** tools `[Read, WebFetch]` with an edge `Read -> WebFetch`, **When** the analyzer runs,
   **Then** a chain with `tools == ["Read", "WebFetch"]`, `risk_level == "critical"` and
   `vulnerability_type == "data_exfiltration"` is reported.
2. **Given** tools `[Read, Grep, Glob]` with every pair connected, **When** the analyzer runs,
   **Then** no chain and no finding is reported (true negative).
3. **Given** tools `[Read, mcp__slack__slack_send_message]`, **When** the analyzer runs, **Then** a
   critical `data_exfiltration` chain is reported (MCP outbound message resolves to the existing
   outbound-message keyword).

### User Story 2 — Unrestricted Bash is a finding on its own (Priority: P1)
A Claude Code agent is granted unscoped `Bash`. Even with no other tool, ZIRAN reports an
unrestricted-execution finding, because `Bash` alone reads files, reaches the network and runs code.

**Independent Test**: Graph with the single tool node `Bash`, no edges; run the analyzer.

**Acceptance Scenarios**:
1. **Given** tools `[Bash]` alone, **When** the analyzer runs, **Then** exactly one finding with
   `tools == ["Bash"]` and `vulnerability_type == "unrestricted_execution"` is reported.
2. **Given** a scoped rule `Bash(git push:*)` (no bare `Bash`), **When** the analyzer runs, **Then**
   no `unrestricted_execution` finding is reported for it.

### User Story 3 — Claude Code specific surfaces (Priority: P2)
Claude Code adds surfaces the pattern set does not model: the `Agent` tool spawns a subagent that
inherits other tools; `Bash` scoped to `git push` pushes local code to a remote; a `Read` of a
secret file (`.env`, SSH keys, cloud credentials) followed by an outbound message leaks secrets.

**Acceptance Scenarios**:
1. **Given** `[Agent, Bash]` with `Agent -> Bash`, **Then** a critical `delegation_to_rce` chain is
   reported.
2. **Given** `[Read, Bash(git push:*)]` with `Read -> Bash(git push:*)`, **Then** a critical
   `code_exfiltration` chain is reported.
3. **Given** `[Read(./.env), mcp__slack__slack_send_message]`, **Then** a critical
   `secret_file_exfiltration` chain is reported (not the generic `data_exfiltration`).

### User Story 4 — Benchmark coverage (Priority: P2)
The ground-truth benchmark gains a vulnerable and a safe Claude Code agent with matching
`tool_chain` scenarios so regressions in this vocabulary show up in `benchmarks/ground_truth/run.py`.

**Acceptance Scenarios**:
1. **Given** the new vulnerable Claude Code scenario, **When** `run.py` runs, **Then** its expected
   chain `[Read, WebFetch]` is found (chain-analyzer TP rises from 12 to 13).
2. **Given** the new safe Claude Code scenario (`Read`, `Grep`, `Glob` only), **When** `run.py`
   runs, **Then** no chain is found (chain-analyzer FP stays 0; scenario-verdict FP stays 3).

### Edge Cases
- Existing tool ids (`read_file`, `Read_File`, `tool_http_request`, `mcp__filesystem__read_file`)
  MUST match exactly as before: resolution is exact and case-sensitive on Claude Code names and
  returns any other id unchanged.
- MCP tool whose final segment repeats the server name (`mcp__slack__slack_send_message`): the
  server-name tokens are skipped before reading the verb.
- MCP tool with a non-outbound verb (`mcp__slack__slack_list_channels`) or a server-only rule
  (`mcp__slack`) is returned unchanged.
- A single-tool finding flows into policy export: the Cedar renderer (which indexes `tools[1]`)
  MUST skip it instead of raising `IndexError`.
- Reported `DangerousChain.tools` and `graph_path` keep the original tool names (`Read`, not
  `read_file`); resolution is used for matching only.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: There MUST be exactly ONE alias map, in `ziran/application/knowledge_graph/tool_aliases.py`,
  exposing `canonical_tool_name(tool_id: str) -> str` and `UNRESTRICTED_EXEC_TOOLS: frozenset[str]`.
  It MUST be pure (stdlib `re` only, no I/O) and importable from both the chain analyzer and the
  trace-analysis path (`ziran/application/trace_analysis/`). No other module may duplicate the map.
- **FR-002**: `canonical_tool_name` MUST resolve, by exact case-sensitive name:
  `Read|Grep|Glob -> read_file`, `Write|Edit|NotebookEdit -> write_file`, `Bash -> shell_execute`,
  `WebFetch -> http_request`, `WebSearch -> browse_url`, `Agent -> spawn_subagent`.
  All targets except `spawn_subagent` are existing capability keywords of `chain_patterns.yaml`.
- **FR-003**: `canonical_tool_name` MUST resolve `mcp__<server>__<tool>` to `send_email` (the
  existing outbound-message keyword) when the first token of `<tool>` that is not a token of
  `<server>` is one of `send`, `post`, `create`, `reply`, `publish`, `update` (tokens split on
  `_`/`-`, lower-cased). Any other MCP name MUST be returned unchanged.
- **FR-004**: `canonical_tool_name` MUST accept the Claude Code permission-rule form
  `Name(specifier)`: the base name resolves per FR-002, except (a) a file-read name whose specifier
  matches a secret-file path (`.env`/`.env.*`, `.ssh/`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`,
  `.aws/credentials`, `.netrc`, `.npmrc`, `.pypirc`, `*.pem`, `*.key`, `*.p12`, `*.pfx`) resolves to
  `read_secret_file`, and (b) `Bash` whose specifier contains `git push` resolves to `git_push`.
- **FR-005**: `ToolChainAnalyzer` MUST apply `canonical_tool_name` wherever it derives the matching
  form of a tool id (`_match_pattern` and the candidate pre-computation in `_find_indirect_chains`).
  Node ids, `DangerousChain.tools`, `graph_path` and evidence MUST keep original names.
- **FR-006**: `chain_patterns.yaml` MUST gain a `claude_code` category, placed first in the file
  (first match wins in `_match_pattern`), with these patterns:
  `spawn_subagent -> shell_execute` (`delegation_to_rce`, critical),
  `spawn_subagent -> http_request` (`cross_agent_exfiltration`, high),
  `spawn_subagent -> write_file` (`cross_agent_persist`, high),
  `read_file -> git_push` (`code_exfiltration`, critical),
  `read_secret_file -> send_email` (`secret_file_exfiltration`, critical).
- **FR-007**: `ToolChainAnalyzer.analyze()` MUST emit one single-tool finding per tool node whose
  id is in `UNRESTRICTED_EXEC_TOOLS` (`{"Bash", "Bash(*)"}`): `tools=[id]`, `graph_path=[id]`,
  `vulnerability_type="unrestricted_execution"`, `risk_level="high"`, `chain_type="direct"`, with
  description and remediation text. It goes through the existing dedupe/score/sort path.
- **FR-008**: `CedarRenderer.render` (`ziran/infrastructure/policy_renderers/cedar_renderer.py`) MUST return a skipped policy for any finding whose tool
  count is not exactly 2 (today it only skips `> 2` and raises `IndexError` on 1).
- **FR-009**: The ground-truth dataset MUST gain `agents/vulnerable_claude_code.yaml`,
  `agents/safe_claude_code.yaml`, `scenarios/tool_chain/tp_011_claude_code_read_webfetch_exfil.yaml`
  (expects chain `[Read, WebFetch]`, `data_exfiltration`, critical) and
  `scenarios/tool_chain/tn_009_safe_claude_code_readonly.yaml` (`expected_chains: []`);
  `validate.py` MUST pass and `README.md` counts MUST be updated.
- **FR-010**: `docs/concepts/tool-chains.md` MUST document the Claude Code alias table, the MCP
  outbound rule, the `Name(specifier)` form and the unrestricted-`Bash` finding.
- **FR-011**: No new runtime dependency; no network or LLM calls in tests; hexagonal layering kept
  (`tool_aliases.py` is application layer and imports nothing outside stdlib).

### Key Entities
- **Canonical tool name**: the capability keyword a tool id is matched as (`read_file`,
  `shell_execute`, ...). Existing ids map to themselves.
- **Single-tool finding**: a `DangerousChain` with one tool, used for `unrestricted_execution`.

### Assumptions (conservative readings, recorded instead of a clarify round)
- "Network read" for `WebSearch` maps to the existing `browse_url` keyword (untrusted web content
  in), not `http_request`; so `[Read, WebSearch]` is not an exfiltration chain.
- "Outbound message" maps to the existing `send_email` keyword, so every existing
  `* -> send_email` pattern applies to MCP send/post/create/reply/publish/update tools.
- The prompt says the MCP tool's final segment "starts with" a verb; the issue's own example
  `mcp__slack__slack_send_message` starts with the server name, so server-name tokens are skipped
  first (FR-003). This satisfies both texts without matching verbs anywhere in the name.
- Tool lists carry no call arguments, so "Bash + git push" and "secret file read" are expressed
  through Claude Code's permission-rule syntax (`Bash(git push:*)`, `Read(./.env)`), as used in
  `allowed-tools` frontmatter and settings permissions.
- Unrestricted execution is `high`, not `critical`: nearly every Claude Code agent has `Bash`, and
  #421 keys its non-zero exit code on critical matches. Only bare `Bash` / `Bash(*)` count as
  unrestricted; scoped `Bash(...)` rules still resolve to `shell_execute` for chain matching.
- Alias matching is case-sensitive so lower-case ids from other frameworks (`read`, `bash`) keep
  their current behaviour.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: The four issue acceptance checks pass as unit tests: `[Read, WebFetch]` critical
  data-exfiltration; `[Bash]` unrestricted-execution; `[Read, Grep, Glob]` nothing; benchmark gains
  safe + vulnerable Claude Code cases.
- **SC-002**: Every pre-existing test in `tests/unit/test_chain_analyzer.py`,
  `tests/unit/test_chain_patterns.py` and `tests/unit/test_analyzer_service.py` passes unchanged.
- **SC-003**: `benchmarks/ground_truth/run.py`: chain analyzer TP=13 FP=0 FN=7 (was 12/0/7);
  scenario verdict FP stays 3; `validate.py` reports 22 agents, 56 scenarios (30 TP, 26 TN).
- **SC-004**: A trace session `Read` then `WebFetch` analysed by `AnalyzerService` yields a critical
  chain with no trace-path code change (the alias lives inside the analyzer).
- **SC-005**: All gates pass — ruff, ruff format, mypy (strict), pytest coverage >= 85%.

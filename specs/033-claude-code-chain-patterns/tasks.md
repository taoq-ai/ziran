# Tasks: Tool-chain patterns for Claude Code built-in and MCP tool names

Test-first: every implementation task is preceded by a test task that MUST be run and seen
failing before the implementation lands. All tests `@pytest.mark.unit`, no network, no LLM.
Graph helper for analyzer tests: `AttackKnowledgeGraph`, `add_tool` per id, `add_tool_chain([a, b], 0.5)`
per edge (all ordered pairs where the story says "every pair connected").

## Phase 1 — Alias module (FR-001..FR-004)

- [x] T001 [US1] Failing tests `tests/unit/test_tool_aliases.py`:
      parametrized `canonical_tool_name` table — `Read|Grep|Glob -> read_file`,
      `Write|Edit|NotebookEdit -> write_file`, `Bash -> shell_execute`, `WebFetch -> http_request`,
      `WebSearch -> browse_url`, `Agent -> spawn_subagent`;
      MCP: `mcp__slack__slack_send_message`, `mcp__slack__slack_post_message`,
      `mcp__slack__slack_reply_to_thread`, `mcp__github__create_issue`,
      `mcp__github__update_pull_request`, `mcp__x__publish_post` -> `send_email`;
      unchanged: `mcp__slack__slack_list_channels`, `mcp__filesystem__read_file`, `mcp__slack`;
      rule form: `Read(./.env)`, `Read(~/.ssh/id_rsa)`, `Grep(.aws/credentials)`, `Read(certs/server.pem)`
      -> `read_secret_file`; `Read(src/main.py)` -> `read_file`; `Bash(git push:*)`,
      `Bash(git push origin main)` -> `git_push`; `Bash(npm test:*)` -> `shell_execute`;
      unchanged (regression): `read_file`, `Read_File`, `read`, `bash`, `tool_http_request`, `harmless_a`;
      `UNRESTRICTED_EXEC_TOOLS == frozenset({"Bash", "Bash(*)"})`.
- [x] T002 [US1] Implement `ziran/application/knowledge_graph/tool_aliases.py` per plan §1
      (stdlib `re` only, module docstring naming it the single shared vocabulary for #417/#421).
      T001 green; `uv run mypy ziran/` clean.

## Phase 2 — Analyzer wiring + Claude Code patterns (FR-005, FR-006)

- [x] T003 [US1][US3] Failing tests in `tests/unit/test_chain_analyzer.py` (new class
      `TestClaudeCodeToolNames`):
      - `[Read, WebFetch]`, edge Read->WebFetch: a chain with `tools == ["Read", "WebFetch"]`,
        `risk_level == "critical"`, `vulnerability_type == "data_exfiltration"` (issue acceptance 1);
      - `[Read, Grep, Glob]`, every ordered pair connected: `analyze() == []` (issue acceptance 3);
      - `[Read, mcp__slack__slack_send_message]`: critical `data_exfiltration`;
      - `[Agent, Bash]`, edge Agent->Bash: critical `delegation_to_rce`;
      - `[Read, Bash(git push:*)]`, edge Read->Bash(git push:*): critical `code_exfiltration`;
      - `[Read(./.env), mcp__slack__slack_send_message]`: `vulnerability_type ==
        "secret_file_exfiltration"`, critical (proves ordering: specific pattern beats generic);
      - reported `tools`/`graph_path` contain original names, never canonical keywords.
- [x] T004 [US1][US3] Implement: wire `canonical_tool_name` into `_match_pattern` and
      `_find_indirect_chains` (`ziran/application/knowledge_graph/chain_analyzer.py`, plan §2); add the
      `claude_code` section FIRST in `ziran/application/knowledge_graph/chain_patterns.yaml` with the
      five FR-006 patterns + header category entry (plan §3). T003 green; all pre-existing tests in
      `test_chain_analyzer.py` / `test_chain_patterns.py` pass unchanged.
- [x] T005 [US1] Failing-first guard for the trace path in `tests/unit/test_analyzer_service.py`:
      `_make_session("s1", ["Read", "WebFetch"])` -> `AnalyzerService.analyze` result has a critical
      chain (`critical_chain_count >= 1`). Written before T004 it fails; after T004 it passes with no
      change to `ziran/application/trace_analysis/`. (Order: write with T003, confirm red, then T004.)

## Phase 3 — Unrestricted Bash finding + Cedar guard (FR-007, FR-008)

- [x] T006 [US2] Failing tests in `tests/unit/test_chain_analyzer.py`:
      - graph with the single node `Bash`, no edges: exactly one finding, `tools == ["Bash"]`,
        `vulnerability_type == "unrestricted_execution"`, `risk_level == "high"` (issue acceptance 2);
      - `Bash(*)` alone: same finding;
      - `Bash(git push:*)` alone and `Bash(npm test:*)` alone: no `unrestricted_execution`;
      - `[Read, Grep, Glob]` still `[]` (no single-tool finding for reads).
- [x] T007 [US2] Implement `_find_unrestricted_execution` and call it from `analyze()` (plan §2).
      T006 green.
- [x] T008 [US2] Failing test in `tests/unit/test_cedar_renderer.py`: a `DangerousChain` with
      `tools=["Bash"]` renders with `skipped is True` and no exception.
- [x] T009 [US2] Implement the `len(tools) != 2` guard in
      `ziran/infrastructure/policy_renderers/cedar_renderer.py` (plan §4). T008 green; existing
      `test_render_skipped_for_three_tools` still green.

## Phase 4 — Benchmark ground truth + docs (FR-009, FR-010)

- [x] T010 [US4] Add `benchmarks/ground_truth/agents/vulnerable_claude_code.yaml`,
      `benchmarks/ground_truth/agents/safe_claude_code.yaml`,
      `benchmarks/ground_truth/scenarios/tool_chain/tp_011_claude_code_read_webfetch_exfil.yaml`,
      `benchmarks/ground_truth/scenarios/tool_chain/tn_009_safe_claude_code_readonly.yaml` (plan §5).
      Run `uv run python benchmarks/ground_truth/validate.py` (expect 22 agents, 56 scenarios, 30 TP,
      26 TN) and `uv run python benchmarks/ground_truth/run.py` (expect chain analyzer TP=13 FP=0
      FN=7; scenario verdict FP=3; no MISS/FP line for the new scenarios). Before T004 the new TP
      would show as MISS — that is this phase's red check if run early.
- [x] T011 [US4] Update `benchmarks/ground_truth/README.md` counts. Revert
      `benchmarks/results/ground_truth_latest.md` and any `uv.lock` churn from `uv run`.
- [x] T012 Docs: `## Claude Code tool names` section in `docs/concepts/tool-chains.md` (plan §6).

## Phase 5 — Gates

- [x] T013 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). Commit as `feat(chains): ...` (Conventional Commits, no
      Co-Authored-By trailer); PR against `develop`, body `Closes #417`; watch `gh pr checks`.

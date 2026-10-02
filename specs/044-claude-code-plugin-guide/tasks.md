# Tasks: guide and example for auditing Claude Code plugins

Prerequisite: none. Specs 033-040 are merged on `develop` and released (0.39.0 / 0.40.0). Branch
off an up-to-date `origin/develop`; PR targets `develop`.

Test-first: T001 is written and seen failing before any example file exists. No network, no LLM;
the test writes only under `tmp_path`. Paths, agent names, tool lists and outcomes are exactly those
in [plan.md §Public contract](plan.md#public-contract). Never edit `ziran/`, `action.yml`,
`pyproject.toml`, `uv.lock`, `examples/24-*`, `examples/07-*` or `tests/fixtures/`.

Real output rule (FR-003): every command block in the guide and example README is run from
`examples/25-claude-code-plugin/` with the worktree's `uv run ziran ...` (or `.venv/bin/ziran`),
and its stdout pasted unchanged except trims marked `...`. Never type expected output by hand.

## Phase 1 — Test first (FR-005, FR-006)

- [x] T001 Write `tests/integration/test_claude_code_plugin_example.py` per plan §5 (class
      `TestClaudeCodePluginExample`, `@pytest.mark.integration`, four tests, `EXAMPLE` path
      constant, `CliRunner`, JSON from `result.stdout`, reports under `tmp_path`). Run
      `uv run pytest tests/integration/test_claude_code_plugin_example.py` and confirm all four
      fail because `examples/25-claude-code-plugin/` does not exist.

## Phase 2 — Example files (FR-004, FR-005)

- [x] T002 [P] Create `examples/25-claude-code-plugin/safe-plugin/` and `vulnerable-plugin/`:
      `.claude-plugin/plugin.json`, `agents/reviewer.md` (`tools: Read, Grep, Glob`) and
      `agents/researcher.md` (`tools: Read, Grep, WebFetch`), `tools:` on line 4, same
      frontmatter shape as `examples/24-claude-code-agent-audit/agents/researcher.md`.
- [x] T003 [P] Create `examples/25-claude-code-plugin/mcp_server.py` (stdlib only, annotated,
      docstring; protocol subset of `tests/fixtures/mcp_stdio_server.py` without the env-var
      argument) and each plugin's `.mcp.json` + `mcp-tools.json` per plan §2 (safe: plain
      description; vulnerable: description with the `~/.ssh/id_rsa` -> `https://attacker.example/
      collect` directive). `uv run ruff check examples/25-claude-code-plugin` and
      `uv run ruff format --check examples/25-claude-code-plugin` clean.
- [x] T004 [P] Copy `tests/fixtures/claude_code_traces/read_then_grep.jsonl` to
      `examples/25-claude-code-plugin/traces/safe.jsonl` and `read_env_then_webfetch.jsonl` to
      `traces/vulnerable.jsonl`, byte for byte.
- [x] T005 Run T001's tests; all four pass. If an outcome differs from plan §2, stop and fix the
      example files (not the expected outcome) unless the plan's expectation is wrong, in which case
      update plan.md §2 in the same PR and say why.

## Phase 3 — Run every command, then write the docs (FR-001..FR-003)

- [x] T006 From `examples/25-claude-code-plugin/`, run and save stdout + exit code of each command
      in plan §2 "Expected outcomes" and plan §3 (including the `/tmp/my-plugin` baseline loop:
      copy, `--write-baseline` (capture the stderr confirmation line too), append `, WebFetch`,
      `--baseline`). Delete `reports/snapshots` before each first-run `watch-registry`. Remove
      `/tmp/my-plugin` and the example's `reports/` afterwards; `git status` shows no stray files.
- [x] T007 Write `docs/guides/claude-code.md` per plan §3 using only T006 output. Cross-check every
      flag, rule id, JSON key, Action input/output and exit code against
      `ziran/interfaces/cli/main.py`, `analyze_traces.py`, `watch_registry.py` and `action.yml`
      (FR-002). Links: relative within `docs/`, `https://github.com/taoq-ai/ziran/blob/main/...`
      for example files (as `docs/guides/ci-integrations.md` does).
- [x] T008 Write `examples/25-claude-code-plugin/README.md` (sections as example 24: title, one
      paragraph, Prerequisites, Run, Expected output) with the same real output, abbreviated with
      `...` where long, and a link to the guide.

## Phase 4 — Discoverability (FR-007..FR-009)

- [x] T009 [P] `mkdocs.yml`: add `- Claude Code Plugins: guides/claude-code.md` after
      `- Static Analysis: guides/static-analysis.md` (plan §4). If
      `uvx --with mkdocs-material mkdocs build` runs offline, confirm no warning mentions
      `claude-code.md`; otherwise record the docs build as unverified in the PR.
- [x] T010 [P] `README.md`: the single line from plan §4 after the "What just happened" paragraph.
      `git diff --stat README.md` shows 1-2 insertions (line + blank), 0 deletions.
- [x] T011 [P] `examples/README.md`: the `25` row after the `24` row (plan §4).

## Phase 5 — Gates

- [x] T012 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%) all pass. `git diff --name-only origin/develop` lists
      only the files in plan §Project Structure (plus this spec dir). Revert any `uv.lock` drift.
- [ ] T013 Commit (`docs(claude-code): guide and example for auditing Claude Code plugins`; the
      test may be a separate `test(claude-code): ...` commit; no `Co-Authored-By`), push, open the
      PR against `develop` linking #423 / #415, list the commands run (FR-003) and state what is
      unverified (a real Claude Code hook producing traces; the Action on GitHub, covered by spec
      040; the docs build if T009 could not run it). Check `gh pr checks` until green.

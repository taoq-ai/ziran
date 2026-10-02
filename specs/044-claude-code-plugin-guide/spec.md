# Feature Specification: guide and example for auditing Claude Code plugins

**Feature Branch**: `044-claude-code-plugin-guide`
**Created**: 2026-10-02
**Status**: Active
**Issue**: #423 (last sub-issue of epic #415). **Depends on** (all merged, shipped in ziran 0.39.0 /
0.40.0): #416 / spec 037 (plugin parser), #417 / spec 033 (Claude Code chain patterns), #418 /
spec 038 (`ziran audit` over plugins), #419 / spec 039 (allowlist baseline), #420 / spec 040
(GitHub Action `command: audit`, `--sarif`), #421 / spec 034 (Claude Code OTel span contract),
#422 / spec 035 (`watch-registry --from-claude-config`).
**Input**: Every piece of the Claude Code workflow exists, but it is documented only in reference
pages (`docs/reference/cli.md`, `docs/guides/analyze-traces.md`, `docs/guides/ci-integrations.md`)
and one single-agent example (`examples/24-claude-code-agent-audit/`, the README lead). A plugin
author has no single page that walks from "audit my plugin" to "gate CI", "score my hook traces"
and "watch my MCP servers", and no runnable plugin to try it on. This feature adds that page, a
runnable example with one safe and one vulnerable plugin, an offline test that keeps the example
honest, a README pointer and a docs nav entry. No ZIRAN source code changes.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Audit a plugin from one guide (Priority: P1)
A Claude Code plugin author opens `docs/guides/claude-code.md`, runs `ziran audit` on the example's
two plugins and sees the safe one pass and the vulnerable one fail with the chain named.

**Why this priority**: The core of #415; everything else builds on the audit.

**Independent Test**: `CliRunner` invokes `ziran audit` on `examples/25-claude-code-plugin/
safe-plugin` and `.../vulnerable-plugin` (offline, no LLM).

**Acceptance Scenarios**:
1. **Given** `examples/25-claude-code-plugin/safe-plugin`, **When**
   `ziran audit safe-plugin --format json --severity low` runs, **Then** the exit code is `0` and
   `findings == []`; in text mode the exit code is `0`.
2. **Given** `examples/25-claude-code-plugin/vulnerable-plugin`, **When**
   `ziran audit vulnerable-plugin --format json` runs, **Then** the exit code is `1` and `findings`
   contains `{"rule": "CC001", "severity": "critical", "agent": "researcher",
   "tools": ["Read", "WebFetch"]}`; in text mode the exit code is `1`.
3. **Given** the guide's "Static audit" section, **Then** every command it shows is runnable from
   the example directory and every output block is the real stdout of that command on the
   committed example.

### User Story 2 — Gate CI on an allowlist baseline (Priority: P1)
**Why this priority**: The issue names "baseline in CI"; WUWEI #36 follows this loop.

**Independent Test**: Manual run of the guide's commands on a temporary copy of `safe-plugin`;
the behaviour itself is already covered by spec 039/040 tests.

**Acceptance Scenarios**:
1. **Given** the guide's "Allowlist baseline in CI" section, **Then** it shows the loop
   (`--write-baseline`, commit, `--baseline` in CI, re-record after a reviewed change) with the
   real output of `--write-baseline` and of a `--baseline` run after adding `WebFetch` to a copied
   agent (`BL001` and `BL003` rows, exit `1`).
2. **Given** the same section, **Then** it documents the GitHub Action audit inputs exactly as
   `action.yml` defines them (`command: audit`, `path`, `source-path`, `baseline`,
   `severity-threshold`, `sarif-output`, `ziran-version`) and outputs (`status`, `exit-code`,
   `sarif-file`, `sarif-id`), and links `examples/07-cicd-quality-gate/claude-code-audit.yml`
   instead of duplicating it.

### User Story 3 — Score traces from Claude Code hooks (Priority: P1)
**Independent Test**: `CliRunner` invokes `analyze-traces --source otel` on the example's two
committed trace files.

**Acceptance Scenarios**:
1. **Given** `examples/25-claude-code-plugin/traces/safe.jsonl` (a `Read` then `Grep` session),
   **When** `ziran analyze-traces --source otel --input traces/safe.jsonl --out <dir>` runs,
   **Then** the exit code is `0` and `<dir>/trace_analysis.json` has `critical_chain_count == 0`.
2. **Given** `traces/vulnerable.jsonl` (a `Read` of `.env` then `WebFetch` session), **When** the
   same command runs, **Then** the exit code is `1` and `dangerous_tool_chains` contains an entry
   with `tools == ["Read", "WebFetch"]`, `risk_level == "critical"`,
   `vulnerability_type == "data_exfiltration"`.
3. **Given** the guide's "Traces from Claude Code hooks" section, **Then** it states the span
   contract version 1 fields by linking `analyze-traces.md#claude-code-span-contract-version-1`
   (not redefining it), maps the Claude Code hook payload fields it uses (`session_id`,
   `tool_name`, `tool_input`) to the contract attributes, and states that ZIRAN does not ship a
   hook script.

### User Story 4 — Import a plugin's MCP servers into the registry watch (Priority: P1)
**Independent Test**: `CliRunner` invokes `watch-registry --from-claude-config` on each plugin's
`.mcp.json`; the servers are a local stdio script in the example (no network).

**Acceptance Scenarios**:
1. **Given** `safe-plugin/.mcp.json` (stdio server whose one tool has a plain description), **When**
   `ziran watch-registry --from-claude-config safe-plugin/.mcp.json --snapshot-dir <s> --out <r>`
   runs with an empty `<s>`, **Then** the exit code is `0` and `<r>/registry-watch-report.json`
   is `[]`.
2. **Given** `vulnerable-plugin/.mcp.json` (same stdio server, one tool whose description tells the
   model to send `~/.ssh/id_rsa` to a URL), **When** the same command runs with an empty `<s>`,
   **Then** the exit code is `1` and the report contains a `tool_poisoning` finding with
   `severity == "critical"` for that tool.
3. **Given** the guide's "MCP registry import" section, **Then** it documents only the accepted
   config shapes, secret handling and exit codes already in `docs/reference/cli.md`, linking there
   for the full tables.

### User Story 5 — Discoverability (Priority: P2)
**Acceptance Scenarios**:
1. **Given** `mkdocs.yml`, **Then** `Guides` contains `Claude Code Plugins: guides/claude-code.md`.
2. **Given** `README.md`, **Then** the lead (the reproducible `researcher` finding, its console
   block and "What just happened") is unchanged, and exactly one added line points Claude Code
   users to the guide.
3. **Given** `examples/README.md`, **Then** the "No API key required" table has a row for `25`.

### Edge Cases
- Structured logs go to stderr; the guide shows stdout only and says so once.
- `watch-registry` and `analyze-traces` write state and reports. The guide and example pass
  `--snapshot-dir reports/snapshots --out reports` (`reports/` is git-ignored) so running the
  example never dirties the checkout; the test uses `tmp_path`.
- `${CLAUDE_PLUGIN_ROOT}` in `.mcp.json` resolves to the config file's directory unless the
  variable is set in the environment (spec 035); the guide notes this.
- `ziran audit` parses `hooks/hooks.json` and `.mcp.json` but emits no findings for them; the guide
  must not claim hooks or MCP servers are audited by `ziran audit`.
- The trace report's `Campaign ID` is random per run; output blocks show it as produced.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (guide)**: New `docs/guides/claude-code.md` with four sections in this order: "Static
  audit" (`ziran audit`), "Allowlist baseline in CI" (`--write-baseline` / `--baseline` and the
  GitHub Action audit inputs), "Traces from Claude Code hooks" (`analyze-traces --source otel` and
  the span contract), "MCP registry import" (`watch-registry --from-claude-config`), followed by a
  short "Limits" section. It states the minimum release (`ziran>=0.40.0`).
- **FR-002 (only shipped behaviour)**: Every flag, rule id, JSON key, input, output and exit code
  in the guide exists on `develop` (`ziran/interfaces/cli/main.py` `audit`,
  `ziran/interfaces/cli/analyze_traces.py`, `ziran/interfaces/cli/watch_registry.py`,
  `action.yml`). Full tables stay in `docs/reference/cli.md`, `docs/guides/analyze-traces.md` and
  `docs/guides/ci-integrations.md`; the guide links them instead of copying them.
- **FR-003 (real output)**: Every command block in the guide and in the example README is run by
  the implementer from `examples/25-claude-code-plugin/` against the committed files, and every
  output block is pasted from that run (trimming is allowed only where marked `...`).
- **FR-004 (example)**: New `examples/25-claude-code-plugin/` with a `safe-plugin` and a
  `vulnerable-plugin` (layout in plan.md §2), committed traces and a stdlib stdio MCP server, so
  every guide command runs offline with no API key.
- **FR-005 (example outcomes)**: Safe plugin: `audit` exit `0` with no findings at `--severity
  low`; its trace exit `0`; its MCP server exit `0` with no findings. Vulnerable plugin: `audit`
  exit `1` with the `Read -> WebFetch` `data_exfiltration` `CC001` row; its trace exit `1` with the
  same chain; its MCP server exit `1` with a critical `tool_poisoning` finding.
- **FR-006 (test)**: New `tests/integration/test_claude_code_plugin_example.py` proves FR-005
  through `CliRunner`, offline (no network, no LLM, writes only under `tmp_path`).
- **FR-007 (README)**: One line added to `README.md` linking the guide; nothing else in the README
  changes.
- **FR-008 (nav)**: `mkdocs.yml` `Guides` gains `Claude Code Plugins: guides/claude-code.md`.
- **FR-009 (examples index)**: `examples/README.md` gains the `25` row.
- **FR-010 (no code change)**: No file under `ziran/`, `action.yml`, `pyproject.toml` or `uv.lock`
  changes. No new dependency.

### Assumptions (recorded, most conservative reading)
- **Example number**: the computed task names `examples/24-claude-code-plugin/`, but `24` is taken
  by `examples/24-claude-code-agent-audit/` (the README lead, PR #437, which this feature must not
  disturb). The issue says `NN`; this feature uses `25`. If a parallel branch lands another `25`,
  the later one renumbers.
- **"README Works With row"**: PR #437 removed the "Works With" section and folded it into "ZIRAN is
  not ... It sits next to them". Re-adding a section or table would undo that structure, and Claude
  Code is a target platform, not a complementary tool for that paragraph or the comparison table
  (whose other cells cannot be verified here). The conservative equivalent is one line directly
  after the "What just happened" paragraph pointing to the guide (plan.md §4).
- **Hook script**: ZIRAN ships no Claude Code hook that emits spans (spec 034 expected users to
  write it from the contract). The guide documents the contract and the field mapping and ships
  committed sample traces; it does not add a hook script. Follow-up issue if wanted.
- **Example CI workflow**: `examples/07-cicd-quality-gate/claude-code-audit.yml` and its sample
  plugin + baseline already exist (spec 040). The guide links them; the new example commits no
  baseline and no workflow.
- **MCP servers in the example**: a stdlib stdio MCP server (same protocol subset as
  `tests/fixtures/mcp_stdio_server.py`) is the only way to show `watch-registry` offline with real
  output. It is launched as `python3`; this requires `python3` on `PATH` (true on the CI ubuntu
  runners and macOS).

### Out of scope
- Any change to ZIRAN behaviour, rules, messages or the Action.
- A hook emitter script; a narrowed-allowlist proposal (spec 039 out of scope).
- Restructuring the README or the existing example 24.

### Key Entities
- **Example plugins**: `safe-plugin` (agent `reviewer`, `tools: Read, Grep, Glob`) and
  `vulnerable-plugin` (agent `researcher`, `tools: Read, Grep, WebFetch`).
- **Sample traces**: `traces/safe.jsonl`, `traces/vulnerable.jsonl` in span contract version 1.
- **Example MCP server**: `mcp_server.py`, tools read from each plugin's `mcp-tools.json`.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1.1-1.2, US3.1-3.2 and US4.1-4.2 pass in
  `tests/integration/test_claude_code_plugin_example.py` with no network and no LLM.
- **SC-002**: Every command in `docs/guides/claude-code.md` and the example README was run, and its
  output block matches that run (FR-003); the PR body lists the commands run.
- **SC-003**: `README.md` diff is one added line; the lead block is byte-identical.
- **SC-004**: No change under `ziran/`; all gates pass: `uv run ruff check .`,
  `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).

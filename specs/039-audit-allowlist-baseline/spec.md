# Feature Specification: allowlist baseline so CI fails when an agent's tools widen

**Feature Branch**: `039-audit-allowlist-baseline`
**Created**: 2026-09-29
**Status**: Active
**Issue**: #419 (part of epic #415). **Depends on**: #418 / spec `038-audit-claude-code-plugins`
(`ziran audit` over Claude Code plugins: `audit_claude_code`, `agent_chains`, `StaticFinding.agent`
/ `.tools`, the `scan` and `report` locals in `audit()`, rows `{rule, severity, file, line, message,
agent, tools}`), which depends on #416 / spec `037-claude-code-plugin-parser` (`load_claude_code`,
`ClaudeCodeScan`, `ClaudeCodeAgent`, fixtures under `tests/fixtures/claude_code/`).
**Consumers (implemented in parallel against [plan.md §Public contract](plan.md#public-contract))**:
#420 (GitHub Action `baseline` input, SARIF for `audit`), #423 (guide).
**Downstream**: WUWEI #36 runs the ZIRAN action in audit mode over its `agents/` directory with a
committed allowlist baseline; a PR that adds `WebFetch` to its `builder` agent must fail CI naming
the chain it creates. WUWEI pins the release and writes an adapter against the flags, baseline file
format, JSON and exit codes below, so they are a stable contract.
**Input**: #418 makes `ziran audit PATH` report every dangerous chain of every Claude Code agent.
A plugin whose agents legitimately hold chains (every WUWEI agent declares `Bash`, so every run has
`CC001` findings) cannot gate CI on "no critical finding"; it needs to accept today's grants and
fail only when an agent's tools widen. Teams want least-privilege agents to STAY least-privilege.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Record the accepted allowlist (Priority: P1)
A plugin maintainer runs `ziran audit agents/ --write-baseline allowlist.json` and commits the file.
It lists each agent's declared tools and every chain finding accepted with them.

**Why this priority**: Nothing can be compared without a baseline; WUWEI commits it once.

**Independent Test**: `CliRunner` over `tests/fixtures/claude_code/vulnerable_plugin`; load the
written file and assert its content and the exit code.

**Acceptance Scenarios**:
1. **Given** the vulnerable fixture plugin, **When**
   `ziran audit PATH --write-baseline B` runs, **Then** `B` is written with `version == 1`,
   `agents.researcher.tools == ["Read", "Grep", "WebFetch", "mcp__slack__send_message"]`,
   `agents.generalist.tools is null`, and `agents.researcher.chains` contains
   `{"tools": ["Read", "WebFetch"], "vulnerability_type": "data_exfiltration",
   "severity": "critical"}`; agents are sorted by name and chains by `tools`.
2. **Given** the same run, **Then** the audit output is the same as a `--baseline B` run against the
   file just written: no `CC001`, `SA003`, `SA004`, `SA007` or `BL*` rows remain, so the exit code
   is `0` in text mode and in JSON mode (also with `--severity low`).
3. **Given** the same plugin written twice, **Then** both files are byte-identical (stable diffs).

### User Story 2 — A widened agent fails naming agent, tool and chain (Priority: P1)
**Why this priority**: The issue's first acceptance criterion and WUWEI #36's.

**Independent Test**: `tmp_path/agents/builder.md` with `tools: Read, Glob, Grep, Bash, Write,
Edit` (the WUWEI builder), write a baseline, append `, WebFetch`, run with `--baseline`.

**Acceptance Scenarios**:
1. **Given** a baseline recorded for `builder` and the agent now declaring `WebFetch` too, **When**
   `ziran audit agents/ --baseline B --format json` runs, **Then** the exit code is `1`,
   `findings` contains `{"rule": "BL001", "severity": "critical", "agent": "builder",
   "tools": ["WebFetch"], "line": 4}` whose `message` is
   `"Agent 'builder' gains tool 'WebFetch' not in the baseline"`, and a row
   `{"rule": "BL003", "severity": "critical", "agent": "builder", "tools": ["Read", "WebFetch"]}`
   whose `message` is
   `"Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch not in the baseline"`.
2. **Given** the same change, **When** run in text mode, **Then** the exit code is `1` and stdout
   names `builder`, `WebFetch` and `Read -> WebFetch`.
3. **Given** the same change, **When** run with `--format json --severity critical`, **Then** the
   exit code is still `1` (violation rows are `critical`).
4. **Given** the same change, **Then** the rows for tools and chains the baseline already accepts
   (`Bash`, `Bash -> Write`, ...) are absent: only the widening is reported.

### User Story 3 — A narrowed agent passes and the narrowing is reported (Priority: P1)
**Acceptance Scenarios**:
1. **Given** a baseline recorded for the vulnerable plugin and `researcher` no longer declaring
   `WebFetch`, **When** `ziran audit PATH --baseline B --format json` runs, **Then** the exit code
   is `0`, no `BL*` row exists, and `baseline.narrowed` contains
   `{"agent": "researcher", "change": "tool_removed", "tools": ["WebFetch"]}` and
   `{"agent": "researcher", "change": "chain_removed", "tools": ["Read", "WebFetch"]}`.
2. **Given** the same change in text mode, **Then** the exit code is `0` and stdout names
   `researcher`, `tool_removed` and `WebFetch`.
3. **Given** the same change with `--format json --severity low`, **Then** the exit code is `0`
   (narrowings are not findings).

### User Story 4 — Other widenings fail (Priority: P1)
**Acceptance Scenarios**:
1. **Given** a baseline where `builder` declares tools and the file now has no `tools` key,
   **When** run with `--baseline`, **Then** exit `1` with a `BL002` `critical` row for `builder`
   at `line == 1`, `tools == []`, message
   `"Agent 'builder' lost its 'tools' key and now inherits every tool"`, and no `BL001` rows for
   that agent (its inherited chains are `BL003` rows).
2. **Given** a baseline without agent `helper` and a new `agents/helper.md` declaring `Read`,
   **When** run with `--baseline`, **Then** exit `1` with a `BL004` `critical` row
   `"Agent 'helper' is not in the baseline"` whose `tools == ["Read"]`.
3. **Given** a baseline whose `builder` entry lists the current tools but omits one currently
   detected chain (a chain pattern added in a newer ZIRAN, simulated by deleting it from the file),
   **When** run with `--baseline`, **Then** exit `1` with exactly one `BL003` row for that chain and
   no `BL001` row.
4. **Given** a baseline and a broken agent file (the #416 `malformed` shape), **When** run with
   `--baseline`, **Then** the `CC000` row is `critical` and the exit code is `1` in text mode: an
   agent that cannot be parsed cannot be compared, so a broken file never passes as "agent removed".

### User Story 5 — Invalid use is a usage error (Priority: P2)
**Acceptance Scenarios**:
1. `--baseline B --write-baseline C` together: exit `2`.
2. `--baseline B` where `B` does not exist: exit `2` (Click).
3. `--baseline B` where `B` is not valid JSON, or fails the schema (missing `version`, `version`
   other than `1`, unknown key, `tools` not a list or `null`): exit `2`; the message names the
   problem kind and key path only, never file content.
4. `--baseline B` or `--write-baseline B` over a `PATH` with no Claude Code definitions (a Python
   project): exit `2`, `"no Claude Code agent definitions found under PATH"`.

### User Story 6 — Nothing changes without the flags (Priority: P1)
**Acceptance Scenarios**:
1. **Given** no `--baseline` / `--write-baseline`, **When** `ziran audit` runs in any mode,
   **Then** output, JSON keys and exit codes are exactly those of spec 038 (and of spec 036 for
   Python-only paths); every existing test passes unmodified; the JSON top level has no
   `baseline` key.

### Edge Cases
- Tool strings are compared verbatim. `Bash` -> `Bash(npm test:*)` reports `BL001` for the scoped
  entry (plus a `tool_removed` narrowing for `Bash`): fail-closed, the maintainer re-records.
- An agent recorded unrestricted (`tools: null`) that now declares a list is a narrowing
  (`tools_key_added`); no `BL001` rows (every tool was already inherited).
- An agent renamed is `agent_removed` (narrowing) plus `BL004` (violation): fails.
- An agent deleted is `agent_removed` and passes, unless `scan.issues` is non-empty (US4.4).
- A narrowed baseline is not rewritten automatically. Until the maintainer re-runs
  `--write-baseline`, re-adding a removed tool passes; the narrowing report says so.
- Python findings and `SA001` (secrets) in agents are never accepted by a baseline: they keep
  their severity and today's exit rules.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (flags)**: `ziran audit` gains `--baseline FILE` (existing file) and
  `--write-baseline FILE`. Both are optional and mutually exclusive (exit `2`). Either requires
  `scan.detected` (exit `2` otherwise).
- **FR-002 (baseline file)**: JSON, `{"version": 1, "agents": {<name>: {"tools": [...] | null,
  "chains": [{"tools": [...], "vulnerability_type": str, "severity": str}]}}}`. Keys are agent
  names (unique per scan, #416). `tools` is the declared list verbatim, `null` when the agent has no
  `tools` key. `chains` are `agent_chains(agent)` at record time. Unknown keys are rejected.
- **FR-003 (write)**: `--write-baseline FILE` builds the baseline from `scan.agents` (skipping
  nothing parsed), writes it UTF-8 with 2-space indent, agents sorted by name, chains sorted by
  `tools`, trailing newline, then continues exactly as `--baseline FILE` would. A confirmation
  line goes to stderr. A write failure exits `2`.
- **FR-004 (compare)**: For each current agent, against its baseline entry:
  - not in baseline -> `BL004`; all its chains are new (`BL003`).
  - baseline restricted, current unrestricted -> `BL002`; chains compared as usual.
  - both restricted -> one `BL001` per declared tool not in the baseline list (declared order);
    one `tool_removed` narrowing per baseline tool no longer declared (baseline order).
  - baseline unrestricted, current restricted -> `tools_key_added` narrowing.
  - chains: one `BL003` per current chain whose `tools` is not a baseline chain's `tools`; one
    `chain_removed` narrowing per baseline chain no longer present.
  Each baseline agent absent from the scan -> `agent_removed` narrowing.
- **FR-005 (accepted findings)**: With a baseline, every `CC001` row is removed (accepted ones are
  dropped, unaccepted ones are replaced by `BL003`); an `SA003`/`SA004` row is removed when its tool
  is in the agent's baseline list or the baseline entry is unrestricted; an `SA007` row is removed
  when the baseline entry is unrestricted. `CC000` rows become `critical`. All other rows (Python,
  `SA001`, unaccepted `SA003`/`SA004`/`SA007`) are unchanged.
- **FR-006 (violation rows)**: `BL001`..`BL004` are `critical` `StaticFinding`s with `file =
  agent.file`, `line = agent.line_of("tools")`, `agent = agent.name` and the exact messages,
  `tools` and recommendations in plan.md. They are appended after the remaining findings, per agent
  in scan order: BL004, BL002, BL001, BL003.
- **FR-007 (exit codes)**: Unchanged rules of spec 036/038 applied to the transformed report:
  text `1` iff a `critical` row remains; JSON `1` iff any row remains with `--severity`, else iff a
  `critical` row remains; `2` usage error. Because violations are `critical`, any widening exits
  `1` under every `--severity`. Narrowings never affect the exit code.
- **FR-008 (JSON)**: With either flag, the document gains one top-level key
  `"baseline": {"narrowed": [{"agent": str, "change": "tool_removed" | "tools_key_added" |
  "agent_removed" | "chain_removed", "tools": [str, ...]}]}` (`[]` when nothing narrowed). Rows keep
  the seven 038 keys. Without the flags, no `baseline` key.
- **FR-009 (text)**: With either flag and at least one narrowing, a "Baseline" panel lists each
  narrowing as `<agent>: <change> <tools joined by ' -> '>` and tells the user to re-record with
  `--write-baseline`, printed before the findings table.
- **FR-010 (layering)**: Models and comparison live in
  `ziran/application/static_analysis/claude_code_baseline.py` (imports domain + application only).
  JSON file read/write is done in the CLI with the model's own `model_validate_json` /
  `model_dump_json`; no `model_dump()` of a scan or agent.
- **FR-011 (docs)**: `docs/reference/cli.md` `ziran audit` documents both flags, the file format,
  the BL rules, the `baseline` JSON key and exit behaviour; the `audit` docstring gains an example.

### Assumptions (recorded, most conservative reading)
- "Fails when a new chain appears" is enforced by `BL003` (critical) for any chain not in the
  baseline, whatever its own risk level, so a gate at `--severity critical` still fails.
- "The accepted chain findings" = every `CC001` chain of the agent at record time (all severities),
  not only critical ones. Accepted tool grants also accept their `SA003`/`SA004`/`SA007` rows;
  otherwise a `--severity high` gate could never pass for an agent with `Bash`.
- Violations are findings (so SARIF, #420, carries them); narrowings are informational and appear
  only in the `baseline` JSON key and the text panel.
- `--write-baseline` exits by the same rules as `--baseline` against the file just written, so it
  can run in a build step without failing on accepted chains; secrets and parse issues still fail.
- Parse issues are escalated to `critical` in baseline mode only; without the flags `CC000` stays
  `high` (spec 038).
- **Out of scope**: the optional "propose a narrowed allowlist per agent" (a minimum set of tools
  whose removal closes every critical chain, rendered like `export-policy`). It needs a hitting-set
  heuristic, a new output and its own tests; nothing in #419's or WUWEI #36's acceptance needs it.
  Follow-up issue if wanted.

### Key Entities
- **AuditBaseline** (`version`, `agents`), **BaselineAgent** (`tools`, `chains`),
  **BaselineChain** (`tools`, `vulnerability_type`, `severity`), **BaselineNarrowing** (`agent`,
  `change`, `tools`): Pydantic models in the application module.
- **Rule ids**: BL001 (tool gained), BL002 (`tools` key lost), BL003 (chain not in baseline),
  BL004 (agent not in baseline).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US5 pass through `CliRunner` over the #416 fixtures and `tmp_path` agents.
- **SC-002**: The WUWEI case (US2.1) passes with an `agents/` directory as `PATH`.
- **SC-003**: Every pre-existing test passes unmodified (US6).
- **SC-004**: No agent system prompt or description text appears in the baseline file or stdout.
- **SC-005**: All gates pass: ruff, ruff format, mypy strict, pytest coverage >= 85%; no new
  runtime dependency; no network or LLM in tests.

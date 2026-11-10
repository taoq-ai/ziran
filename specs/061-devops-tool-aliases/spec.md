# Feature Specification: map read_secrets and execute_command to existing chain capabilities

**Feature Branch**: `ziran-devops-alias`
**Created**: 2026-10-29
**Status**: Active
**Track**: SLICE (two alias entries, one test file, one docs table; under ten tasks)
**Base**: `develop` @ 8943b83
**Input**: an agent with `read_secrets` and `execute_command` gets no chain from
`ToolChainAnalyzer.analyze(include_cycles=False)`, because no pattern side recognises either
id. Add anchored aliases, in the form spec 056 added, that map both ids to capabilities the
existing patterns already use, so an existing pattern pair fires. No pattern change.

## The item in my own words

A DevOps agent that can read secrets and run shell commands can pass a production credential
to a command. ziran reports nothing for that pair today: `read_secrets` has the keywords `read`
and `secrets`, `execute_command` has `execute` and `command`, and no pattern side matches
either by substring or keyword overlap.

The fix is two alias entries, not a pattern. `read_secrets` resolves to `secrets_manager` and
`execute_command` to `execute_code`. The existing `secrets_manager` to `execute_code` pattern
(`cloud_secret_to_rce`, critical) then fires. The aliases are anchored: only the whole id, after
lowercasing and removing separators, with an optional `tool` prefix and `results`/`json` suffix,
is mapped. Ids with other words around the name keep their own words, and `mcp__` ids are never
mapped. `update_config` and `deploy_service` stay unmapped: no pattern side has a config-write
keyword, and `deploy_service` already matches the `deploy` targets.

Done means:

1. `canonical_tool_name` maps `read_secrets`, `tool_read_secrets` and `ReadSecrets` to
   `secrets_manager`, and `execute_command`, `tool_execute_command` and `ExecuteCommand` to
   `execute_code`. Ids with other words around them stay unchanged.
2. A graph with `read_secrets` and `execute_command` linked both ways gives exactly one chain
   with cycles off, over those two ids, type `cloud_secret_to_rce`.
3. Every existing case in `tests/unit/test_tool_aliases.py` keeps its result.
4. On the ziran-paper dev split, dev chain gt_fw_tp_002#0 moves from missed to found, and no
   other dev result moves.

## Study note: these aliases are post-hoc

This change comes from the ziran-paper study's dev-split error analysis
(`study/analysis/dev_fn_analysis.md` in taoq-ai/ziran-paper), which classes gt_fw_tp_002#0 as a
missing capability mapping. The study's corpus data was first seen on 2026-10-09T08:26:11Z.
Under the study's decision D-1, every pattern, alias or classifier change after that time is
post-hoc, and corpus findings these aliases produce fall under the owner's answer on alias
changes in the study-v1 addendum. The fix used dev-split scenario ids only, from ziran-paper's
`data/ground_truth_split.json`. No held-out scenario file was opened, `run.py` was not run over
all scenarios, no corpus data was read and no ground-truth label changed.

## Current behaviour (read on `develop` @ 8943b83)

- `canonical_tool_name` (`ziran/application/knowledge_graph/tool_aliases.py`) returns
  `read_secrets`, `execute_command`, `update_config` and `deploy_service` unchanged.
- `ToolChainAnalyzer._match_pattern` canonicalises both ids, then takes the first pattern whose
  source and target match by substring or keyword overlap.
- Pattern sides that name secrets are `read_secret_file` (target `send_email`) and
  `secrets_manager` (targets `http_request` and `execute_code`). Execution sides are
  `execute_code`, `shell_execute` and `shell`. No pattern pairs a secret source with
  `shell_execute`.
- On the four-tool DevOps set (`deploy_service`, `read_secrets`, `execute_command`,
  `update_config`) the analyzer finds no chain, cycles on or off.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The DevOps tool names resolve (Priority: P1)

**Independent Test**: `canonical_tool_name` on each id.

**Acceptance Scenarios**:
1. `read_secrets`, `tool_read_secrets`, `ReadSecrets` give `secrets_manager`.
2. `execute_command`, `tool_execute_command`, `ExecuteCommand` give `execute_code`.
3. `read_secret`, `read_secrets_from_vault`, `safe_execute_command`,
   `execute_command_and_send_email`, `mcp__vault__read_secrets`, `mcp__shell__execute_command`,
   `update_config` and `deploy_service` are returned unchanged.

### User Story 2 - Secret read then command execution is reported (Priority: P1)

**Independent Test**: an in-memory `AttackKnowledgeGraph` with every tool pair linked both
ways (the ground-truth runner's graph shape) and `analyze(include_cycles=False)`.

**Acceptance Scenarios**:
1. `read_secrets` with `execute_command` gives exactly one chain, `read_secrets` to
   `execute_command`, type `cloud_secret_to_rce`, risk critical.
2. The four-tool DevOps set gives that same single chain.

### User Story 3 - Nothing that resolved before changes (Priority: P1)

**Acceptance Scenarios**:
1. Every existing case in `tests/unit/test_tool_aliases.py` keeps its result.
2. `chain_patterns.yaml` is byte-identical to `develop` @ 8943b83.

### User Story 4 - Dev split (Priority: P2)

**Acceptance Scenarios**:
1. ziran-paper `study/scripts/p5.py --side dev` with the branch head as `--v1-sha` scores
   gt_fw_tp_002#0 as found, cycles off and on; it is missed at `develop` @ 8943b83.
2. No other of the 11 dev expected chains changes, and ziran-paper
   `study/scripts/dev_benchmark.py run` gives the same chain and verdict counts at both heads.

### Edge Cases

- **Reach of `execute_command`.** It now takes every pattern with an `execute_code` side, as
  source or target. For example `read_file` to `execute_command` is reported as `file_to_rce`,
  and `execute_command` to `shell_execute` gets the existing `execute_code` to `shell_execute`
  type. The reach follows the matching every other aliased name uses.
- **Reach of `read_secrets`.** It also takes `secrets_manager` to `http_request`
  (`cloud_secret_exfiltration`).
- **Cycles on.** With cycle search on, the four-tool set also gives cycle chains through
  `deploy_service` and `update_config`, typed `cloud_secret_to_rce`; the study's P5 counts the
  two-tool chain.
- **Singular and longer names.** `read_secret`, `get_secrets` and `read_secrets_from_vault` are
  not mapped. Each alias is one exact name, as in spec 056.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: add `readsecrets` -> `secrets_manager` and `executecommand` -> `execute_code` to
  `_FRAMEWORK_ALIASES`, so they take the anchored match spec 056 defined (US1).
- **FR-002**: no change to `chain_patterns.yaml`, `chain_analyzer.py`, the classifier or any
  ground-truth label (US3).
- **FR-003**: `docs/concepts/tool-chains.md` lists both names.
- **FR-004**: no new dependency.

### Assumptions

- **`execute_command` maps to `execute_code`, not `shell_execute`.** The tool runs shell
  commands, which `Bash` maps to `shell_execute`, but no existing pattern pairs a secret source
  with `shell_execute`, so that mapping would leave the chain unreported without a pattern
  change, which is out of scope. Arbitrary command execution includes code execution, and every
  `execute_code` pattern reads as true for a command runner. Overturn: a reviewer wants
  `shell_execute` plus a new secret-to-shell pattern, which needs its own item.
- **`read_secrets` maps to `secrets_manager`, not `read_secret_file`.** `read_secret_file`
  stands for Claude Code `Read` rules on secret paths, and with `execute_code` it would match
  only through the generic `read_file` pattern (`file_to_rce`). `secrets_manager` is the
  existing pattern side for secret-store reads and gives `cloud_secret_to_rce`. Overturn: a
  reviewer reads `read_secrets` as a file read.
- **`update_config` and `deploy_service` stay unmapped.** The promise allows them only where an
  existing pattern keyword fits; none fits `update_config`, and `deploy_service` already matches.
- **Spec number 061.** The item named `specs/059-devops-tool-aliases/`, but 059 and 060 were
  taken by the plugin specs before this branch.

## Success Criteria *(mandatory)*

- **SC-001**: the US1 and US2 tests fail on 8943b83 and pass after the change.
- **SC-002**: every existing test passes unchanged.
- **SC-003**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
  `uv run pytest --cov=ziran` (coverage at least 85%) pass.
- **SC-004**: US4 holds.

## Clarifications

### Session 2026-10-29

- Q: Add a `secrets_manager` to `shell_execute` pattern so `execute_command` can map to
  `shell_execute`? A: no. The item rules out pattern changes; if no existing pair fired, the
  item would close unfixed. One does fire.
- Q: Map `update_config` to a write capability? A: no. No pattern side has a config-write
  keyword, so a mapping would be a guess with no chain to show for it.

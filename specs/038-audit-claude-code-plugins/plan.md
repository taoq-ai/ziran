# Implementation Plan: `ziran audit` over Claude Code plugins with static checks and declared-tool chains

**Branch**: `038-audit-claude-code-plugins` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)
**Issue**: #418 (epic #415) | **Builds on**: #416 contract (`specs/037-claude-code-plugin-parser/
plan.md` §Public contract, branch `037-claude-code-plugin-parser`), #417 (released), spec 036
(released). **Consumers**: #419 (baseline), #420 (action/SARIF), #423 (docs) build against
§Public contract in parallel; WUWEI #36 pins the release.

## Summary
One new application module turns a `ClaudeCodeScan` (#416) into the existing `AnalysisReport`:
per agent, SA001 (secret regexes over prompt/description/tools), SA003 (dangerous declared tool),
SA004 (wildcard grant), SA007 (no `tools` key) and CC001 (one finding per `DangerousChain` from
`ToolChainAnalyzer` over a complete graph of the declared tools); plus CC000 per parse issue.
`ziran audit` calls the parser, appends these findings to the unchanged Python report, and adds two
JSON keys (`agent`, `tools`) only when Claude Code definitions were detected. Two small edits to
existing code: `StaticFinding` gains two defaulted fields, and `ToolChainAnalyzer.analyze` gains
`include_cycles` (cycle enumeration on a complete graph is exponential; measured below).

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Click (CLI), existing `StaticAnalyzer`/`StaticAnalysisConfig`,
`AttackKnowledgeGraph` + `ToolChainAnalyzer` (NetworkX), #416 `load_claude_code` and domain
models. No new dependencies.
**Storage**: N/A.
**Testing**: pytest; `@pytest.mark.unit` for the application module and analyzer option (in-memory
`ClaudeCodeAgent`/`ClaudeCodeScan`); CLI acceptance via `CliRunner` in the existing
`TestAuditCommand` class (that file carries no markers; add none). Fixtures: #416's
`tests/fixtures/claude_code/` (not modified) plus `tmp_path` agents. No network, no LLM.
**Target Platform**: `ziran audit` CLI and the GitHub Action (`command: audit`).
**Project Type**: single Python package (`ziran/`).
**Performance Goals**: an unrestricted agent (12 built-ins, 132 edges) audits in ~0.02 s.
Measured on `develop` @ 778fc0d with a complete digraph: cycles enabled -> 5 tools 83 chains,
6 -> 570, 7 -> 3,300, 8 -> 19,969 (0.11 s), 12 -> ~10^8 simple cycles (does not terminate in
practice); cycles disabled -> 12 tools 29 chains, 0.023 s. On a complete graph every pair has a
direct edge, so `_find_indirect_chains` returns nothing and costs one `has_edge` per candidate.
**Constraints**: mypy strict; line length 100; application layer imports no infrastructure.
**Scale/Scope**: 1 new source module, 3 edited source files, 1 new test file, 2 extended test
files, 1 docs section.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | `ziran/application/static_analysis/claude_code_audit.py` imports domain (`claude_code`, `capability`) and application (`analyzer`, `knowledge_graph`) only. The CLI (interfaces) imports the #416 infrastructure parser and the application module, as it already does for `claude_mcp_config` in `watch-registry`. |
| II. Type safety | PASS | All functions annotated. `StaticFinding` stays the existing frozen dataclass (extended, not replaced); the JSON dict is CLI-edge serialisation, as in spec 036. |
| III. Tests | PASS | Test-first per task; unit tests for the module and the analyzer option; CLI acceptance tests over the committed #416 fixtures. |
| IV. Async-first | PASS (justified) | Same sync path as the existing `audit` command and `StaticAnalyzer`; local files only, no network. |
| V. Extensibility | PASS | SA001 reuses the configurable `secret_checks`; chain rules come from `chain_patterns.yaml`. No new port. |
| VI. Simplicity | PASS | One module, two public functions, no new model, no new CLI flag, no new output format. The analyzer option is one `if`. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #418 implementer and for #419/#420/#423, which are implemented in parallel before
this code exists. Names, signatures, JSON keys and exit codes MUST NOT change without updating this
file.

### 1. `ziran/application/static_analysis/analyzer.py` (edit) — `StaticFinding`

Append two defaulted fields at the end (all existing constructions use keywords; order-safe):
```python
@dataclass(frozen=True)
class StaticFinding:
    check_id: str
    message: str
    severity: Literal["critical", "high", "medium", "low"]
    file_path: str
    line_number: int | None = None
    context: str = ""
    recommendation: str = ""
    agent: str | None = None          # new: Claude Code agent name; None for Python and CC000
    tools: tuple[str, ...] = ()       # new: verbatim tool strings (chain order for CC001)
```
`StaticAnalyzer`, `AnalysisReport` and `_run_check` are otherwise unchanged.

### 2. `ziran/application/knowledge_graph/chain_analyzer.py` (edit) — `ToolChainAnalyzer.analyze`

```python
def analyze(self, *, include_cycles: bool = True) -> list[DangerousChain]:
    ...
    if include_cycles:
        chains.extend(self._find_chain_cycles(tool_nodes, pattern_cache))
```
Default `True`: every existing caller (`result_builder`, `pentesting/tools/graph.py`,
`trace_analysis/analyzer_service.py`) and test is unchanged. Docstring step 3 notes the flag.

### 3. `ziran/application/static_analysis/claude_code_audit.py` (new)

```python
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.static_analysis.analyzer import AnalysisReport, StaticFinding, _run_check
from ziran.application.static_analysis.config import StaticAnalysisConfig
from ziran.domain.entities.capability import DangerousChain
from ziran.domain.entities.claude_code import (
    ClaudeCodeAgent, ClaudeCodeScan, claude_code_tool_capability,
)

def agent_chains(agent: ClaudeCodeAgent) -> list[DangerousChain]:
    """Dangerous chains over the agent's declared (or inherited) tool set. No execution."""
    # graph = AttackKnowledgeGraph()
    # for cap in agent.capabilities: graph.add_capability(cap.id, cap)
    # for a, b in itertools.permutations(agent.effective_tools, 2):
    #     graph.add_tool_chain([a, b], risk_score=0.5)
    # return ToolChainAnalyzer(graph).analyze(include_cycles=False)

def audit_claude_code(
    scan: ClaudeCodeScan, config: StaticAnalysisConfig | None = None
) -> AnalysisReport:
    """Static findings for every agent in *scan*; files_analyzed = scan.files_analyzed."""
```
`config` defaults to `StaticAnalysisConfig.default()`; the CLI passes `StaticAnalyzer().config` so
custom secret rules apply. Nothing else is public.

**Finding order**: all CC000 (in `scan.issues` order), then per agent in `scan.agents` order:
SA001 (ascending line), SA003 and SA004 (declared-tool order), SA007, CC001 (analyzer order: risk
score descending).

**Rules** (`file_path = agent.file` and `agent = agent.name` unless stated; `T = agent.line_of("tools")`):

| Rule | Severity | When | `line_number` | `tools` | `message` (exact) |
|---|---|---|---|---|---|
| CC000 | `high` | each `scan.issues` entry | `issue.line` (may be `None`) | `()` | `issue.message` (value-free by #416); `file_path = issue.file`, `agent = None` |
| SA001 | check severity (`critical`) | any `config.secret_checks` pattern matches a line of the virtual file below | matched line | `()` | the check's `message` (`"Potential secret or API key in source code"`) |
| SA003 | `high` | per declared tool (skip when `agent.unrestricted`) with `claude_code_tool_capability(tool).dangerous` | `T` | `(tool,)` | `f"Agent '{agent.name}' is granted dangerous tool '{tool}'"` |
| SA004 | `medium` | per declared tool that is a wildcard grant: `tool.endswith("(*)")`, or `tool.startswith("mcp__")` and (`tool.count("__") < 2` or `"*" in tool`) | `T` | `(tool,)` | `f"Agent '{agent.name}' is granted wildcard tool '{tool}'"` |
| SA007 | `high` | `agent.unrestricted` | `T` (= 1) | `()` | `f"Agent '{agent.name}' has no 'tools' key and inherits every tool"` |
| CC001 | `chain.risk_level` | each `DangerousChain` from `agent_chains(agent)` | `T` | `tuple(chain.tools)` | `f"Agent '{agent.name}': {chain.vulnerability_type} via {' -> '.join(chain.tools)}"` |

Recommendations (fixed strings, one per rule; shown by the text renderer):
- CC000 `"Fix the agent file so Claude Code and ZIRAN can parse it."`
- SA003 `"Remove the tool or scope it with a permission rule, e.g. Bash(npm test:*)."`
- SA004 `"Replace the wildcard with the specific tools the agent needs."`
- SA007 `"Add a 'tools' list with only the tools the agent needs."`
- CC001 `"Remove one tool of the chain from the agent's 'tools' list, or split the agent."`
- SA001 keeps the check's own recommendation.

**SA001 virtual file** (no file re-read): `lines = [""] * (agent.body_line - 1) +
agent.system_prompt.splitlines()`; then, when non-empty, `lines[agent.line_of("description") - 1]
= agent.description.replace("\n", " ")` and, when `agent.tools is not None`,
`lines[agent.line_of("tools") - 1] = ", ".join(agent.tools)`. Run
`_run_check(check, lines, agent.file)` for each `config.secret_checks` entry and set `agent` with
`dataclasses.replace`. Line numbers are therefore real file lines. `context` holds the matched line
and is never emitted (spec 036).

**CC001 uniqueness**: direct chains are one per ordered pair and `unrestricted_execution` is one per
tool, so `(agent, tools)` identifies a CC001 finding. #419 keys accepted chains by
`(agent, list(tools))`.

### 4. `ziran/interfaces/cli/main.py` (edit) — `audit`

No new flag, no new exit code. Body after `target = Path(path)`:
```python
from ziran.application.static_analysis.claude_code_audit import audit_claude_code
from ziran.infrastructure.config.claude_code_plugin import load_claude_code

analyzer = StaticAnalyzer()
scan = load_claude_code(target)   # local name `scan`: #419 reads it for --baseline

if target.is_file() and scan.detected:
    report = AnalysisReport()
elif target.is_file():
    report = AnalysisReport(files_analyzed=1, findings=analyzer.analyze_file(target))
else:
    report = analyzer.analyze_directory(target)

if scan.detected:
    cc = audit_claude_code(scan, analyzer.config)
    report.files_analyzed += cc.files_analyzed
    report.findings.extend(cc.findings)
# existing --severity filter, JSON branch and _display_audit_report follow unchanged, except:
```
JSON rows:
```python
row = {"rule": f.check_id, "severity": f.severity, "file": f.file_path,
       "line": f.line_number, "message": f.message}
if scan.detected:
    row |= {"agent": f.agent, "tools": list(f.tools)}
```

**JSON document** (`--format json`, stdout only; logs stay on stderr):
```json
{
  "files_analyzed": 5,
  "findings": [
    {
      "rule": "CC001",
      "severity": "critical",
      "file": "tests/fixtures/claude_code/vulnerable_plugin/agents/researcher.md",
      "line": 4,
      "message": "Agent 'researcher': data_exfiltration via Read -> WebFetch",
      "agent": "researcher",
      "tools": ["Read", "WebFetch"]
    }
  ]
}
```
- Claude Code mode (`scan.detected`): every row has exactly
  `{rule, severity, file, line, message, agent, tools}`; `agent` is `null` for Python rows and
  CC000, `tools` is `[]` when not applicable.
- Otherwise: exactly the five 036 keys (unchanged).
- `file` is the path string as discovered by the parser (relative when `PATH` is relative).

**Exit codes** (unchanged from spec 036, applied to the merged report):

| Code | Text mode | JSON mode |
|---|---|---|
| `0` | no `critical` finding | no finding at/above `--severity`; without `--severity`, no `critical` finding |
| `1` | any `critical` finding | any finding at/above `--severity`; without `--severity`, any `critical` |
| `2` | usage error (missing `PATH`, bad option) | same |

### 5. Guidance for #419 / #420 (not implemented here)
- Baseline input: `scan.agents` (`name`, `tools`, `unrestricted`, `effective_tools`) and the CC001
  findings of `audit_claude_code(scan, ...)` (`agent`, `tools`, `severity`, `message`). To name the
  chain an added tool creates, compare CC001 `(agent, tools)` sets between baseline and current run,
  or call `agent_chains(agent)` directly.
- #419 owns `--baseline` / `--write-baseline` and any baseline-mode exit semantics; it inserts its
  logic after the merge block above, using the local `scan` and `report`.
- #420 owns SARIF for `audit`; it can map `rule`, `severity`, `file`, `line`, `message` from the
  rows above (CC001/SA rules as SARIF rule ids).
- Never `model_dump()` a scan or agent into output (#416 §C).

## Project Structure

### Documentation (this feature)
```text
specs/038-audit-claude-code-plugins/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/application/static_analysis/claude_code_audit.py   # new: agent_chains, audit_claude_code
ziran/application/static_analysis/analyzer.py            # edit: StaticFinding.agent, .tools
ziran/application/knowledge_graph/chain_analyzer.py      # edit: analyze(include_cycles=True)
ziran/interfaces/cli/main.py                             # edit: audit() wiring + JSON keys + docstring
docs/reference/cli.md                                    # edit: ziran audit section
tests/unit/test_claude_code_audit.py                     # new
tests/unit/test_chain_analyzer.py                        # extend: include_cycles
tests/unit/test_cli_main.py                              # extend: TestAuditCommand acceptance
```
**Structure Decision**: single package; the audit use case sits next to `StaticAnalyzer` in
`application/static_analysis` because it produces the same `AnalysisReport`. #416's files and
fixtures are consumed, not modified.

## Prerequisite
#416 (`load_claude_code`, domain models, `tests/fixtures/claude_code/`) must be merged into
`develop` before T004; rebase this branch on it. Until then, T001-T003 can be written against the
§Public contract of spec 037.

## Release note for the implementer
Commit as `feat(audit): audit Claude Code plugins with static checks and declared-tool chains`
(tests may be split as `test(audit): ...`). No `!`, no `BREAKING CHANGE` footer (the JSON change is
additive and only in Claude Code mode), no `Co-Authored-By` trailer. PR targets `develop`, body
links #418 and restates §Public contract names for #419/#420.

## Phases
- P1 (tests first): analyzer option + `StaticFinding` fields (FR-006, FR-007).
- P2 (tests first): `claude_code_audit` module (FR-003..FR-005).
- P3 (tests first): CLI wiring, JSON keys, acceptance over fixtures (FR-001, FR-002, FR-008..FR-010).
- P4: docs (FR-011).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.

## Complexity Tracking
None.

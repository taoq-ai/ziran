# Implementation Plan: static CrewAI project reader for `ziran audit`

**Branch**: `crewai-extractor` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)

## Summary

A new infrastructure loader reads CrewAI projects (agents.yaml and tasks.yaml with
`yaml.safe_load`, crew.py with `ast.parse`) into domain models, one unit per agents.yaml entry.
A new application module turns the scan into `CR000`/`CR001` findings. Chains come from the
construction `agent_chains` already uses, extracted into `tool_chains(tools)` so both sources call
one function. `ziran audit` calls the loader next to the Claude Code loader and, in JSON mode, adds
a `crewai` list of units. A stdlib script samples units from that JSON for a hand check.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: PyYAML `safe_load`/`compose`, stdlib `ast`/`os`/`random`/`argparse`/`json`, Pydantic v2, Click; reuses `tool_chains` and `StaticFinding`. No new dependencies.
**Storage**: N/A (reads project files only).
**Testing**: pytest with `@pytest.mark.unit`; `tmp_path` projects for the loader; committed
fixtures under `tests/fixtures/crewai/` for CLI acceptance through `CliRunner` in the existing
`TestAuditCommand` class (no markers there, as today).
**Target Platform**: `ziran audit` CLI.
**Project Type**: single Python package (`ziran/`).
**Performance Goals**: linear in file size; each file at most 1 MiB; chain construction as for
Claude Code (no cycle search).
**Constraints**: mypy strict; line length 100; untrusted input (no import, exec or eval; bounded
size and AST depth; every failure is an issue).
**Scale/Scope**: 3 new source modules, 2 edited source files, 1 script, 3 new test files,
1 extended test file, fixtures, 1 docs section.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | Domain models in `ziran/domain/entities/crewai.py` import only pydantic. The loader in `ziran/infrastructure/config/crewai_project.py` imports domain only. `ziran/application/static_analysis/crewai_audit.py` imports domain and application. The CLI wires the loader and the use case, as it does for Claude Code. |
| II. Type safety | PASS | Pydantic models for every unit; all functions annotated. |
| III. Tests | PASS | Test first; unit tests for loader and audit; CLI tests over fixtures. |
| IV. Async-first | PASS (justified) | Same sync path as the existing `audit` and Claude Code loader; local files, no network. |
| V. Extensibility | PASS | Chains come from `chain_patterns.yaml` through the existing analyzer. No new port. |
| VI. Simplicity | PASS | One loader, one audit function, one shared chain function, one script. No CLI flag. |

## Public contract

### 1. `ziran/domain/entities/crewai.py` (new)

```python
class CrewAIIssue(BaseModel):      # message never holds file content
    file: str
    line: int | None = None
    message: str

class CrewAITask(BaseModel):
    name: str
    tools: list[str] = []

class CrewAIAgent(BaseModel):      # one unit = one agents.yaml entry
    name: str
    file: str                      # agents.yaml path
    line: int = 1                  # line of the entry key
    agent_tools: list[str] = []
    tasks: list[CrewAITask] = []   # tasks assigned to this agent
    errors: list[CrewAIIssue] = []
    @property
    def tools(self) -> list[str]: ...   # agent tools, then task tools, de-duplicated

class CrewAIScan(BaseModel):
    root: str
    agents: list[CrewAIAgent] = []
    issues: list[CrewAIIssue] = []      # project-level: agents.yaml unusable
    files_analyzed: int = 0             # YAML files read
    @property
    def detected(self) -> bool: ...     # any agent or issue
```

### 2. `ziran/infrastructure/config/crewai_project.py` (new)

```python
MAX_AST_DEPTH: Final = 200
def load_crewai(path: Path, skip_dirs: Collection[str] = ()) -> CrewAIScan: ...
```

Never raises for file content or missing files. Reuses `MAX_FILE_BYTES` (1 MiB) from
`claude_code_plugin`. Steps per project directory `d` (holding `agents.yaml` and `tasks.yaml`):

1. Read agents.yaml (containment, size, decode, `safe_load`, `compose` for key lines). Failure or a
   non-mapping document: one scan issue, no units.
2. Read tasks.yaml the same way. Failure: an error on every unit.
3. Find `d.parent / "crew.py"`, then `d / "crew.py"`. Read, `ast.parse`, check depth. Failure: an
   error on every unit, YAML data kept.
4. Collect `@agent` and `@task` functions (decorator `agent`/`task` as a name, attribute or call).
   In each, the first call to `Agent`/`Task` (name or attribute) gives `config=` key, `tools=` and,
   for tasks, `agent=`. Tool element names follow FR-007: a map of simple assignments in crew.py
   (one callee per name) resolves names; other elements become `ast.unparse` text.
5. Apply FR-004 to FR-006.

### 3. `ziran/application/static_analysis/claude_code_audit.py` (edit)

```python
def tool_chains(tools: list[str]) -> list[DangerousChain]:
    """One capability node per tool, an edge per ordered pair, analyze(include_cycles=False)."""

def agent_chains(agent: ClaudeCodeAgent) -> list[DangerousChain]:
    return tool_chains(agent.effective_tools)
```

`agent.capabilities` is `[claude_code_tool_capability(t) for t in agent.effective_tools]`, so the
graph is the same node for node.

### 4. `ziran/application/static_analysis/crewai_audit.py` (new)

```python
def audit_crewai(scan: CrewAIScan) -> AnalysisReport: ...
```

Order: `CR000` per scan issue, then per unit its `CR000` errors and its `CR001` chains (analyzer
order).

| Rule | Severity | file / line | agent | tools |
|---|---|---|---|---|
| CR000 | high | issue file / issue line | unit name or None | () |
| CR001 | chain risk level | agents.yaml / entry line | unit name | chain tools |

CR001 message: `Agent '<name>': <vulnerability_type> via <a> -> <b>`.

### 5. `ziran/interfaces/cli/main.py` (edit, `audit`)

`crew = load_crewai(target, analyzer.config.skip_directories)`. A file target that yields a scan
skips the Python analyzer, as for Claude Code. JSON rows carry `agent` and `tools` when either
source is detected. When `crew.detected`, the document has `crewai`:

```json
{"agent": "researcher", "file": ".../config/agents.yaml", "line": 1,
 "tools": ["FileReadTool", "send_email"], "agent_tools": ["FileReadTool"],
 "tasks": [{"name": "research_task", "tools": ["send_email"]}], "errors": []}
```

`--baseline` and `--write-baseline` stay Claude Code only. `CR` findings pass through
`apply_baseline` unchanged (it only drops `CC001` and accepted `SA00x`).

### 6. `scripts/sample_crewai_units.py` (new)

`python scripts/sample_crewai_units.py AUDIT_JSON --seed N [--n 50]`. Exit 2 when the file cannot
be read or has no `crewai` list. Prints a header (`seed`, `n`, frame size, units left out for
errors) and one block per sampled unit.

## Project Structure

### Documentation (this feature)

```text
specs/056-crewai-extractor/
├── spec.md
├── plan.md
├── tasks.md
├── analysis.md
└── checklists/requirements.md
```

### Source Code (repository root)

```text
ziran/domain/entities/crewai.py                       (new)
ziran/infrastructure/config/crewai_project.py         (new)
ziran/application/static_analysis/crewai_audit.py     (new)
ziran/application/static_analysis/claude_code_audit.py (edit: tool_chains)
ziran/interfaces/cli/main.py                          (edit: audit)
scripts/sample_crewai_units.py                        (new)
tests/fixtures/crewai/vulnerable_crew/...             (new)
tests/fixtures/crewai/safe_crew/...                   (new)
tests/unit/test_crewai_project.py                     (new)
tests/unit/test_crewai_audit.py                       (new)
tests/unit/test_sample_crewai_units.py                (new)
tests/unit/test_cli_main.py                           (extend TestAuditCommand)
docs/reference/cli.md                                 (CrewAI section)
```

**Structure Decision**: mirror spec 037/038 (domain entities, infrastructure loader, application
audit, CLI wiring), so a reader of the Claude Code path finds the same shape.

## Complexity Tracking

None.

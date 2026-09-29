# Implementation Plan: allowlist baseline so CI fails when an agent's tools widen

**Branch**: `039-audit-allowlist-baseline` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)
**Issue**: #419 (epic #415) | **Builds on**: #418 contract (`specs/038-audit-claude-code-plugins/
plan.md` §Public contract, branch `038-audit-claude-code-plugins`), which builds on #416
(`specs/037-claude-code-plugin-parser/plan.md` §Public contract). **Consumers**: #420 (action
`baseline` input, SARIF), #423 (guide) build against §Public contract in parallel; WUWEI #36 pins the
release.

## Summary
Two new `ziran audit` flags. `--write-baseline FILE` records, per Claude Code agent, the declared
tool list (or `null` when unrestricted) and every chain `agent_chains(agent)` (#418) finds.
`--baseline FILE` compares the current scan with that file: accepted grants and chains drop out of
the report, each widening becomes a `critical` `BL00x` finding (tool gained, `tools` key lost, new
chain, new agent), and narrowings are reported separately without affecting the exit code. Because
violations are ordinary `critical` findings, the existing text/JSON renderers, `--severity` filter
and exit rules apply unchanged, and #420's SARIF carries them with no extra mapping. One new
application module (four Pydantic models, two functions) plus the CLI wiring.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Click, Pydantic v2 (`model_validate_json` / `model_dump_json` for the
baseline file), #418 `agent_chains` / `StaticFinding.agent` / `.tools`, #416 `ClaudeCodeScan`. No
new dependencies.
**Storage**: one user-committed JSON file (the baseline); read and written only by the CLI.
**Testing**: pytest; `@pytest.mark.unit` for the module (in-memory `ClaudeCodeAgent` /
`ClaudeCodeScan` / `StaticFinding`); CLI acceptance through `CliRunner` in a new
`TestAuditBaseline` class in `tests/unit/test_cli_main.py` (that file carries no markers; add
none), over #416's `tests/fixtures/claude_code/` (not modified; copied to `tmp_path` when a test
edits an agent) and `tmp_path` agents. No network, no LLM.
**Target Platform**: `ziran audit` CLI and the GitHub Action (#420 passes `--baseline`).
**Project Type**: single Python package (`ziran/`).
**Performance Goals**: comparison is linear in agents x (tools + chains); chains are computed with
`agent_chains` (cycles off, ~0.02 s for an unrestricted agent, measured in spec 038). Measured on
`develop` @ 778fc0d for the WUWEI builder (`Read, Glob, Grep, Bash, Write, Edit`): 9 chains;
adding `WebFetch` gives 7 new chains, 5 critical, including `Read -> WebFetch`
(`data_exfiltration`).
**Constraints**: mypy strict; line length 100; application layer imports no infrastructure.
**Scale/Scope**: 1 new source module, 1 edited source file, 1 new test file, 1 extended test file,
1 docs section.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | `ziran/application/static_analysis/claude_code_baseline.py` imports domain (`claude_code`) and application (`analyzer`, `claude_code_audit`) only. Baseline file I/O is two calls in the CLI (interfaces), the same edge where `audit` already writes JSON. |
| II. Type safety | PASS | Baseline, entries, chains and narrowings are Pydantic models with `extra="forbid"` at the trust boundary (a committed, hand-editable file); all functions annotated. |
| III. Tests | PASS | Test-first per task; unit tests for build/compare rules; CLI acceptance for every spec scenario including the WUWEI case. |
| IV. Async-first | PASS (justified) | Same sync CLI path as `audit` (spec 036/038); one small local file read. |
| V. Extensibility | PASS | No new port; chain rules stay in `chain_patterns.yaml`. |
| VI. Simplicity | PASS | No new output format, no new exit code, no renderer change: violations are findings. One module, two functions. The optional allowlist proposal is out of scope (spec Assumptions). |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #419 implementer and for #420/#423, which are implemented in parallel before this
code exists. Names, signatures, file format, JSON keys and exit codes MUST NOT change without
updating this file.

### 1. `ziran/application/static_analysis/claude_code_baseline.py` (new)

```python
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from ziran.application.static_analysis.analyzer import StaticFinding
from ziran.application.static_analysis.claude_code_audit import agent_chains
from ziran.domain.entities.claude_code import ClaudeCodeScan

class BaselineChain(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: list[str] = Field(min_length=1)   # DangerousChain.tools, verbatim, chain order
    vulnerability_type: str                  # DangerousChain.vulnerability_type (for reviewers)
    severity: str                            # DangerousChain.risk_level (for reviewers)

class BaselineAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: list[str] | None                  # required; None = recorded without a `tools` key
    chains: list[BaselineChain] = Field(default_factory=list)

class AuditBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]                      # required
    agents: dict[str, BaselineAgent]         # required; key = ClaudeCodeAgent.name

class BaselineNarrowing(BaseModel):
    agent: str
    change: Literal["tool_removed", "tools_key_added", "agent_removed", "chain_removed"]
    tools: list[str] = Field(default_factory=list)
    # tool_removed -> [tool]; chain_removed -> chain tools; tools_key_added / agent_removed -> []

def build_baseline(scan: ClaudeCodeScan) -> AuditBaseline:
    """Baseline of every parsed agent: agents sorted by name, chains sorted by `tools`."""
    # AuditBaseline(version=1, agents={a.name: BaselineAgent(
    #     tools=None if a.tools is None else list(a.tools),
    #     chains=sorted((BaselineChain(tools=c.tools, vulnerability_type=c.vulnerability_type,
    #                                  severity=c.risk_level) for c in agent_chains(a)),
    #                   key=lambda c: c.tools))
    #   for a in sorted(scan.agents, key=lambda a: a.name)})

def apply_baseline(
    findings: list[StaticFinding], scan: ClaudeCodeScan, baseline: AuditBaseline
) -> tuple[list[StaticFinding], list[BaselineNarrowing]]:
    """Return (findings with accepted rows removed and violations appended, narrowings)."""
```
Nothing else is public. The input list is not mutated.

**Kept findings** (original order), from `findings`:
- `CC001`: always removed (accepted ones vanish; unaccepted ones are re-emitted as `BL003`).
- `SA003` / `SA004` with `agent` set: removed when that agent has a baseline entry and
  (`entry.tools is None` or `f.tools[0] in entry.tools`).
- `SA007`: removed when that agent has a baseline entry with `entry.tools is None`.
- `CC000`: kept with `severity="critical"` (`dataclasses.replace`).
- Everything else (Python rows, `SA001`, non-accepted `SA003`/`SA004`/`SA007`): kept unchanged.

**Violations** appended after the kept findings, per `agent` in `scan.agents` order, in this order
(`entry = baseline.agents.get(agent.name)`, `T = agent.line_of("tools")`, current chains
`= agent_chains(agent)`, accepted keys `= {tuple(c.tools) for c in entry.chains}` or `set()`):

| Rule | When | `tools` | `message` (exact) |
|---|---|---|---|
| BL004 | `entry is None` | `tuple(agent.tools or ())` | `f"Agent '{agent.name}' is not in the baseline"` |
| BL002 | `entry.tools is not None and agent.unrestricted` | `()` | `f"Agent '{agent.name}' lost its 'tools' key and now inherits every tool"` |
| BL001 | `entry.tools is not None and not agent.unrestricted`: each `t in agent.tools` (declared order) with `t not in entry.tools` | `(t,)` | `f"Agent '{agent.name}' gains tool '{t}' not in the baseline"` |
| BL003 | each current chain (analyzer order) with `tuple(chain.tools) not in accepted` | `tuple(chain.tools)` | `f"Agent '{agent.name}': new {chain.risk_level} chain {chain.vulnerability_type} via {' -> '.join(chain.tools)} not in the baseline"` |

Every violation: `severity="critical"`, `file_path=agent.file`, `line_number=T`,
`agent=agent.name`, `context=""`, and a fixed recommendation:
- BL001 `"Remove the tool, or review it and re-record the baseline with --write-baseline."`
- BL002 `"Restore the 'tools' list, or review it and re-record the baseline with --write-baseline."`
- BL003 `"Remove one tool of the chain, or review it and re-record the baseline with --write-baseline."`
- BL004 `"Review the new agent's tools and record them with --write-baseline."`

**Narrowings**, per `agent` in `scan.agents` order with an `entry`, in this order:
`tool_removed` for each `t in entry.tools` (baseline order) not in `agent.tools` (only when both
are restricted); `tools_key_added` when `entry.tools is None and not agent.unrestricted`;
`chain_removed` for each `entry.chains` item (baseline order) whose `tuple(tools)` is not a current
chain. Then `agent_removed` for each baseline name (baseline order) not in `scan.agents`.

### 2. Baseline file format (committed by users; `version` 1)

```json
{
  "version": 1,
  "agents": {
    "generalist": {
      "tools": null,
      "chains": [
        {"tools": ["Bash"], "vulnerability_type": "unrestricted_execution", "severity": "high"}
      ]
    },
    "researcher": {
      "tools": ["Read", "Grep", "WebFetch", "mcp__slack__send_message"],
      "chains": [
        {"tools": ["Read", "WebFetch"], "vulnerability_type": "data_exfiltration", "severity": "critical"}
      ]
    }
  }
}
```
(Abbreviated; real files list every chain.) Written as
`baseline.model_dump_json(indent=2) + "\n"`, UTF-8: field order as declared above, agents sorted by
name, chains sorted by `tools`, so two writes of the same scan are byte-identical. Read with
`AuditBaseline.model_validate_json`. Only `vulnerability_type`/`severity` are informational;
comparison uses agent names, `tools` and chain `tools`, all verbatim and case-sensitive. The file
never contains a system prompt, description, hook or MCP value.

### 3. `ziran/interfaces/cli/main.py` (edit) — `audit`

New options (after `--format`), no other flag changes:
```python
@click.option("--baseline", "baseline_path",
              type=click.Path(exists=True, dir_okay=False), default=None,
              help="Fail when a Claude Code agent's tools or chains widen beyond this baseline.")
@click.option("--write-baseline", "write_baseline_path",
              type=click.Path(dir_okay=False), default=None,
              help="Record each Claude Code agent's tools and chains as the accepted baseline.")
def audit(path: str, severity: str | None, fmt: str,
          baseline_path: str | None, write_baseline_path: str | None) -> None:
```
Body (first line of the function, then #418's merge block unchanged, then this block, then the
existing `--severity` filter and output):
```python
if baseline_path and write_baseline_path:
    raise click.UsageError("--baseline and --write-baseline are mutually exclusive")
...  # 038: analyzer, scan = load_claude_code(target), report, merge
narrowed: list[BaselineNarrowing] | None = None
if baseline_path or write_baseline_path:
    if not scan.detected:
        raise click.UsageError("no Claude Code agent definitions found under PATH")
    if write_baseline_path:
        baseline = build_baseline(scan)
        try:
            Path(write_baseline_path).write_text(
                baseline.model_dump_json(indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            raise click.BadParameter(f"cannot write file ({exc.strerror})",
                                     param_hint="--write-baseline") from None
        click.echo(f"Baseline written to {write_baseline_path} "
                   f"({len(baseline.agents)} agents)", err=True)
    else:
        try:
            baseline = AuditBaseline.model_validate_json(
                Path(baseline_path).read_bytes())
        except OSError as exc:
            raise click.BadParameter(f"cannot read file ({exc.strerror})",
                                     param_hint="--baseline") from None
        except ValidationError as exc:
            err = exc.errors(include_input=False, include_url=False)[0]
            loc = ".".join(str(p) for p in err["loc"]) or "document"
            raise click.BadParameter(f"invalid baseline at {loc}: {err['msg']}",
                                     param_hint="--baseline") from None
    report.findings, narrowed = apply_baseline(report.findings, scan, baseline)
```
(`model_validate_json` reports malformed JSON and bad UTF-8 as a `ValidationError` of type
`json_invalid`, whose `msg` carries a position, not content.)

JSON document: `doc = {"files_analyzed": ..., "findings": rows}` as in #418; then
`if narrowed is not None: doc["baseline"] = {"narrowed": [n.model_dump() for n in narrowed]}`.

Text mode: when `narrowed` is non-empty, before `_display_audit_report(report)`, print one
`Panel(title="Baseline narrowed", expand=False)` with one line per narrowing,
`f"{n.agent}: {n.change} {' -> '.join(n.tools)}".rstrip()` passed through
`rich.markup.escape`, and a last line
`"Re-record with --write-baseline to lock in the narrowing."`.

**JSON example** (WUWEI case: `builder` baseline recorded, then `WebFetch` added; abbreviated):
```json
{
  "files_analyzed": 1,
  "findings": [
    {"rule": "SA003", "severity": "high", "file": "agents/builder.md", "line": 4,
     "message": "Agent 'builder' is granted dangerous tool 'WebFetch'",
     "agent": "builder", "tools": ["WebFetch"]},
    {"rule": "BL001", "severity": "critical", "file": "agents/builder.md", "line": 4,
     "message": "Agent 'builder' gains tool 'WebFetch' not in the baseline",
     "agent": "builder", "tools": ["WebFetch"]},
    {"rule": "BL003", "severity": "critical", "file": "agents/builder.md", "line": 4,
     "message": "Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch not in the baseline",
     "agent": "builder", "tools": ["Read", "WebFetch"]}
  ],
  "baseline": {"narrowed": []}
}
```

**Exit codes** (rules of spec 036/038, unchanged, applied after the baseline step):

| Code | Meaning |
|---|---|
| `0` | text: no `critical` row; JSON: no row at/above `--severity` (without it, no `critical` row). With a baseline this means no widening, no parse issue, no other critical finding. Narrowings never change it. |
| `1` | text: any `critical` row; JSON: any row at/above `--severity` (without it, any `critical`). Every `BL00x` row and, with a baseline, every `CC000` row is `critical`. |
| `2` | usage error: both flags; baseline file missing, unreadable, not JSON or not matching §2; write failure; flag used on a `PATH` without Claude Code definitions; plus the existing Click errors. |

### 4. Guidance for #420 / #423 (not implemented here)
- The action's `baseline` input maps to `--baseline <file>`; exit `1` means "widened or failing
  findings", `2` means "misconfigured". Nothing else is needed from this issue.
- SARIF (#420) maps `BL001`..`BL004` like any other row (`rule`, `severity`, `file`, `line`,
  `message`). `baseline.narrowed` is informational and has no SARIF mapping.
- The guide (#423) shows the loop: `ziran audit agents/ --write-baseline agents/ziran-baseline.json`,
  commit, CI runs `--baseline`, re-record after a reviewed change.

## Project Structure

### Documentation (this feature)
```text
specs/039-audit-allowlist-baseline/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/application/static_analysis/claude_code_baseline.py   # new: models, build_baseline, apply_baseline
ziran/interfaces/cli/main.py                                # edit: audit() flags, baseline block, JSON key, text panel, docstring
docs/reference/cli.md                                       # edit: ziran audit "Allowlist baseline"
tests/unit/test_claude_code_baseline.py                     # new
tests/unit/test_cli_main.py                                 # extend: TestAuditBaseline
```
**Structure Decision**: next to #418's `claude_code_audit.py` in `application/static_analysis`, in
its own module so the two parallel branches touch different files. #416's and #418's files and
fixtures are consumed, not modified (except `main.py`'s `audit`, where this feature adds only the
block above).

## Prerequisite
#418 (`038-audit-claude-code-plugins`, itself on #416) must be merged into `develop` before T002;
rebase this branch on it. Until then T001 can be written against the §Public contract of
specs 037/038.

## Release note for the implementer
Commit as `feat(audit): allowlist baseline so CI fails when an agent's tools widen` (tests may be
split as `test(audit): ...`). No `!`, no `BREAKING CHANGE` footer (new flags and a JSON key present
only with them), no `Co-Authored-By` trailer. PR targets `develop`, body links #419 and restates
§Public contract names for #420/#423.

## Phases
- P1 (tests first): module models + `build_baseline` (FR-002, FR-003).
- P2 (tests first): `apply_baseline` rules (FR-004..FR-006).
- P3 (tests first): CLI flags, JSON key, text panel, usage errors, acceptance (FR-001, FR-007..FR-009).
- P4: docs (FR-011).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.

## Complexity Tracking
None.

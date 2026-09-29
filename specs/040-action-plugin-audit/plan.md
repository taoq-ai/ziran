# Implementation Plan: run Claude Code plugin audits from the ZIRAN GitHub Action

**Branch**: `040-action-plugin-audit` | **Date**: 2026-09-29 | **Spec**: [spec.md](spec.md)
**Issue**: #420 (epic #415) | **Builds on**: #419 contract (`specs/039-audit-allowlist-baseline/
plan.md` §Public contract, branch `039-audit-allowlist-baseline`) and #418 (merged, 9a045b1).
**Consumers**: #423 (guide) builds against §Public contract in parallel; WUWEI #36 pins the release.

## Summary
Give `ziran audit` a `--sarif FILE` flag backed by one new function in the existing SARIF module,
then extend the composite action: two inputs (`path`, `baseline`), two outputs (`exit-code`,
`sarif-id`), and an `audit` branch that builds a quoted argument array and passes `--baseline` /
`--sarif`. The action's existing upload step then uploads audit SARIF with no other change. A
sample plugin with a committed baseline plus a new `action-test.yml` job that runs the checkout's
action (`uses: ./`) proves the widened-agent failure, the SARIF content and the upload in CI.
An example workflow for plugin repositories goes next to the other CI templates.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13); composite action in bash.
**Primary Dependencies**: Click, stdlib `json`/`pathlib`; existing `ziran/application/cicd/sarif.py`;
#419 `--baseline`; action uses `actions/setup-python`, `github/codeql-action/upload-sarif`
(both already used). No new dependencies; the action stays bash + `pip` (+ `gh`/`python3` in tests).
**Storage**: N/A. Files: the SARIF output, the user-committed baseline.
**Testing**: pytest. SARIF function: new `TestAuditSarif` class in `tests/unit/test_cicd.py`
(that file carries no markers; add none). CLI: new `TestAuditSarif` class in
`tests/unit/test_cli_main.py` (that file carries no markers; add none), `CliRunner` with
`monkeypatch.chdir(tmp_path)`. Action contract: `tests/unit/test_action_yml.py` (PyYAML, `@pytest.mark.unit`).
End-to-end: new job in `.github/workflows/action-test.yml`. No network, no LLM in pytest.
**Target Platform**: `ziran audit` CLI; GitHub Actions `ubuntu-latest`.
**Performance Goals**: SARIF is linear in rows; negligible.
**Constraints**: mypy strict; line length 100; application layer imports no infrastructure; stdout
of `--format json` stays a single JSON document.
**Scale/Scope**: 2 edited source files (`sarif.py`, `main.py`), `action.yml`, 2 workflows, 1 example
workflow, 1 sample plugin (4 files), 3 docs files, 3 test files (1 new).

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | `generate_audit_sarif` lives in `application/cicd/sarif.py` and imports only `application/static_analysis/analyzer.StaticFinding` (type-only). File write is in the CLI (interfaces), as `ziran ci --sarif` does via `write_sarif`. |
| II. Type safety | PASS | Annotated; SARIF stays `dict[str, Any]` like the existing `generate_sarif` (serialisation format, not domain data). |
| III. Tests | PASS | Test-first per task: unit tests for the mapping, CLI tests for flag/exit/stdout, contract test for `action.yml`, CI job for the action end to end. |
| IV. Async-first | PASS (justified) | Sync CLI entry point, one local file write (same as `audit` JSON and `ci --sarif`). |
| V. Extensibility | PASS | No port change; BL rows need no special SARIF case. |
| VI. Simplicity | PASS | One function + one private envelope helper shared with `generate_sarif`; no new output format, no new exit code, no bash SARIF conversion, no new action. The existing upload step is reused. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #420 implementer and for #423 (implemented in parallel). Names, signatures, flags,
inputs, outputs and exit codes MUST NOT change without updating this file.

### 1. `ziran/application/cicd/sarif.py` (edit)

```python
from collections.abc import Sequence
if TYPE_CHECKING:
    from ziran.application.static_analysis.analyzer import StaticFinding

_SECURITY_SEVERITY: dict[str, str] = {"critical": "9.0", "high": "7.0", "medium": "5.0", "low": "3.0"}

def generate_audit_sarif(findings: Sequence[StaticFinding]) -> dict[str, Any]:
    """SARIF v2.1.0 document for `ziran audit` rows (one result per finding, report order)."""

def _sarif_document(rules: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    """The envelope `generate_sarif` builds today ($schema, version 2.1.0, one run, driver ZIRAN,
    _ZIRAN_VERSION, informationUri, rules, results); `generate_sarif` is refactored to call it
    with byte-identical output (existing TestSarif passes unchanged)."""
```
Nothing else is public; `generate_sarif` / `write_sarif` keep their signatures and output.

Per finding `f` (a `StaticFinding`), in input order:
```python
p = Path(f.file_path)
cwd = Path.cwd()
if p.is_absolute() and p.is_relative_to(cwd):
    p = p.relative_to(cwd)
artifact = ({"uri": p.as_uri()} if p.is_absolute()
            else {"uri": p.as_posix(), "uriBaseId": "%SRCROOT%"})
physical: dict[str, Any] = {"artifactLocation": artifact}
if f.line_number:
    physical["region"] = {"startLine": f.line_number}
result = {
    "ruleId": f.check_id,
    "level": _SEVERITY_TO_SARIF[f.severity],          # existing map: critical/high error, medium warning, low note
    "message": {"text": f.message},
    "locations": [{"physicalLocation": physical}],
}
if f.agent is not None:
    result["properties"] = {"agent": f.agent, "tools": list(f.tools)}
```
Rules: one per distinct `check_id`, in first-seen order:
```python
{"id": check_id,
 "shortDescription": {"text": check_id},
 "help": {"text": <first non-empty recommendation for that id>},      # key omitted if none
 "defaultConfiguration": {"level": _SEVERITY_TO_SARIF[<highest severity seen for that id>]},
 "properties": {"security-severity": _SECURITY_SEVERITY[<highest severity seen for that id>]}}
```
`f.context` is never read. No fingerprints (upload-sarif computes them from the checkout).

### 2. `ziran/interfaces/cli/main.py` (edit) — `audit`

One new option after #419's `--write-baseline`:
```python
@click.option("--sarif", "sarif_path", type=click.Path(dir_okay=False), default=None,
              help="Also write the reported findings as SARIF v2.1.0 (GitHub code scanning).")
def audit(path: str, severity: str | None, fmt: str, baseline_path: str | None,
          write_baseline_path: str | None, sarif_path: str | None) -> None:
```
Placed right after the existing `--severity` filter, before the JSON / text branches (text mode
exits inside `_display_audit_report`, so the file must exist before it):
```python
if sarif_path:
    from ziran.application.cicd.sarif import generate_audit_sarif
    try:
        Path(sarif_path).write_text(
            json.dumps(generate_audit_sarif(report.findings), indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise click.BadParameter(f"cannot write file ({exc.strerror})",
                                 param_hint="--sarif") from None
    click.echo(f"SARIF written to {sarif_path}", err=True)
```
The JSON document, the #419 `baseline` key, the text report and the exit codes are unchanged:

| Code | Meaning (unchanged from spec 036/038/039) |
|---|---|
| `0` | text: no `critical` row; JSON: no row at/above `--severity` (without it, no `critical` row) |
| `1` | findings as above; with `--baseline` every `BL00x` widening is `critical` |
| `2` | usage error, including `--sarif` not writable, missing/invalid baseline |

Docstring examples gain `ziran audit ./my-plugin/ --baseline ziran-baseline.json --sarif audit.sarif`.

### 3. `action.yml` (edit)

New inputs (after `source-path`):
```yaml
  path:
    description: >
      Path to audit (a Claude Code plugin root, an agents/ directory, a .md agent file, or Python
      source). Used by: audit. Overrides source-path when set.
    required: false
    default: ""
  baseline:
    description: >
      Allowlist baseline JSON written by `ziran audit PATH --write-baseline FILE`. Used by: audit.
      The step fails (exit 1) when an agent's tools or chains widen beyond it.
    required: false
    default: ""
```
`sarif-output` description gains "Used by: ci, scan, audit". New outputs:
```yaml
  exit-code:
    description: "ziran exit code. audit: 0 passed, 1 findings or widened agent, 2 could not run (bad path/baseline/input)"
    value: ${{ steps.run.outputs.exit_code }}
  sarif-id:
    description: "Code scanning upload id; empty when no SARIF was uploaded"
    value: ${{ steps.upload.outputs.sarif-id }}
```
`Run ZIRAN` step gains:
```yaml
      env:
        ZIRAN_INPUT_PATH: ${{ inputs.path }}
        ZIRAN_INPUT_SOURCE_PATH: ${{ inputs.source-path }}
        ZIRAN_INPUT_BASELINE: ${{ inputs.baseline }}
        ZIRAN_INPUT_SEVERITY: ${{ inputs.severity-threshold }}
        ZIRAN_INPUT_SARIF: ${{ inputs.sarif-output }}
```
and the `audit)` branch becomes (runs ziran itself, like `scan`):
```bash
          audit)
            AUDIT_ARGS=("${ZIRAN_INPUT_PATH:-$ZIRAN_INPUT_SOURCE_PATH}")
            [ -n "$ZIRAN_INPUT_SEVERITY" ] && AUDIT_ARGS+=(--severity "$ZIRAN_INPUT_SEVERITY")
            [ -n "$ZIRAN_INPUT_BASELINE" ] && AUDIT_ARGS+=(--baseline "$ZIRAN_INPUT_BASELINE")
            [ -n "$ZIRAN_INPUT_SARIF" ] && AUDIT_ARGS+=(--sarif "$ZIRAN_INPUT_SARIF")
            ziran audit "${AUDIT_ARGS[@]}"
            EXIT_CODE=$?
            if [ $EXIT_CODE -eq 2 ]; then
              echo "::error::ziran audit could not run (exit 2): check the path, baseline and severity-threshold inputs"
            fi
            ;;
```
The generic run guard becomes `if [ "$CMD" != "scan" ] && [ "$CMD" != "audit" ]; then`. After
it, before the `status` lines: `echo "exit_code=$EXIT_CODE" >> "$GITHUB_OUTPUT"`. The Upload SARIF
step gains `id: upload` and is otherwise unchanged (`if: always() && ...`, `continue-on-error:
true`). Nothing else in `action.yml` changes (the `scan`/`ci`/`policy` branches keep their current
interpolation; out of scope).

**Action contract summary** (what WUWEI #36 / #423 use):
```yaml
- uses: taoq-ai/ziran@v0
  with:
    command: audit
    path: agents                         # or "." for a plugin root
    baseline: agents/ziran-baseline.json
    severity-threshold: low              # default; widenings are critical and always fail
    sarif-output: ziran-results.sarif    # default; "" disables SARIF and upload
    ziran-version: "ziran==<pinned>"
# outputs: status (passed|failed), exit-code (0|1|2), sarif-file, sarif-id
```
Needs `permissions: {contents: read, security-events: write, actions: read}` for the upload.

### 4. Sample plugin and example (new)
```text
examples/07-cicd-quality-gate/claude-code-plugin/.claude-plugin/plugin.json   {"name": "sample-plugin", "version": "0.1.0"}
examples/07-cicd-quality-gate/claude-code-plugin/agents/builder.md
examples/07-cicd-quality-gate/claude-code-plugin/agents/researcher.md
examples/07-cicd-quality-gate/claude-code-plugin/ziran-baseline.json          # written by --write-baseline, never hand-edited
examples/07-cicd-quality-gate/claude-code-audit.yml                           # workflow for a plugin repo
```
`builder.md` (tools on line 4, benign prompt, no secret-like text):
```markdown
---
name: builder
description: Builds and tests code changes.
tools: Read, Glob, Grep, Bash, Write, Edit
---
You implement small code changes and run the tests.
```
`researcher.md`: same shape, `name: researcher`, `tools: Read, Grep, Glob`. Measured on `develop`
@ 9a045b1 without a baseline: builder has 3 `SA003` and 9 `CC001` (2 critical) rows, researcher
none; with its baseline (#419 rules) every row is accepted, so the run exits `0`.
Record it with `cd examples/07-cicd-quality-gate/claude-code-plugin && ziran audit . --write-baseline ziran-baseline.json`.

`claude-code-audit.yml`: `on: [push, pull_request]`, the permissions above, `actions/checkout@v7`,
`taoq-ai/ziran@v0` with `command: audit`, `path: .`, `baseline: ziran-baseline.json`,
`ziran-version: "ziran>=<release with #419/#420>"`, comments showing record / commit / re-record.

### 5. `.github/workflows/action-test.yml` (edit)
`paths` (push and pull_request) gain `examples/07-cicd-quality-gate/claude-code-plugin/**`.
New job `test-audit-claude-code-plugin` (`runs-on: ubuntu-latest`; workflow already grants
`security-events: write`):
1. `actions/checkout@v7`.
2. Unchanged plugin: `uses: ./` with `command: audit`, `path:` sample, `baseline:` sample baseline,
   `sarif-output: ""`, `ziran-version: "."`, `id: clean`. (Must pass; no `continue-on-error`.)
3. Assert `steps.clean.outputs.exit-code == '0'` and `status == 'passed'`.
4. `cp -r` the sample to `widened-plugin`; `sed -i '4s/$/, WebFetch/' widened-plugin/agents/builder.md`;
   `grep -qx 'tools: Read, Glob, Grep, Bash, Write, Edit, WebFetch' widened-plugin/agents/builder.md`.
5. `uses: ./` with `path: widened-plugin`, `baseline: widened-plugin/ziran-baseline.json`,
   `sarif-output: ziran-audit.sarif`, `ziran-version: "."`, `id: widened`, `continue-on-error: true`.
6. Assert `steps.widened.outcome == 'failure'`, `exit-code == '1'`, `status == 'failed'`,
   `sarif-file == 'ziran-audit.sarif'`; `python3` checks the SARIF per spec US1.2.
7. If `github.event_name == 'push' || (github.event.pull_request.head.repo.full_name ==
   github.repository && github.actor != 'dependabot[bot]')`: assert `steps.widened.outputs.sarif-id != ''`.
8. `uses: ./` with `baseline: does-not-exist.json`, `sarif-output: ""`, `id: misconfigured`,
   `continue-on-error: true`; assert `exit-code == '2'`.
Only step 5 uploads (one upload per job, so no category clash). Existing jobs are unchanged.

`.github/workflows/lint-ci-templates.yml`: add `examples/07-cicd-quality-gate/claude-code-audit.yml`
to `templates` (its `paths` already cover `examples/07-cicd-quality-gate/**`).

### 6. Guidance for #423 (not implemented here)
Link `examples/07-cicd-quality-gate/claude-code-audit.yml` and the §3 contract summary; the guide's
loop is: record (`--write-baseline`), commit, CI (`baseline:` input), re-record after review.
Exit `1` = widened or failing findings, `2` = could not run.

## Project Structure

### Documentation (this feature)
```text
specs/040-action-plugin-audit/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/application/cicd/sarif.py                       # edit: generate_audit_sarif, _sarif_document
ziran/interfaces/cli/main.py                          # edit: audit --sarif
action.yml                                            # edit: inputs path/baseline, outputs exit-code/sarif-id, audit branch
.github/workflows/action-test.yml                     # edit: test-audit-claude-code-plugin job, paths
.github/workflows/lint-ci-templates.yml               # edit: template list
examples/07-cicd-quality-gate/claude-code-audit.yml   # new
examples/07-cicd-quality-gate/claude-code-plugin/     # new (4 files)
examples/07-cicd-quality-gate/README.md               # edit
docs/guides/ci-integrations.md                        # edit: "Claude Code plugin audit" subsection
docs/reference/cli.md                                 # edit: --sarif row for ziran audit
tests/unit/test_cicd.py                               # extend: TestAuditSarif
tests/unit/test_cli_main.py                           # extend: TestAuditSarif
tests/unit/test_action_yml.py                         # new: action contract keys
```
**Structure Decision**: SARIF generation stays in the one SARIF module; the action stays one
composite action; the example sits with the other CI templates so #423 keeps free use of a new
example number.

## Prerequisite
#419 (`039-audit-allowlist-baseline`) must be merged into `develop` before T004 (the CLI option is
declared after `--write-baseline` and the sample baseline is written by `--write-baseline`); rebase
this branch onto it. T001-T002 (SARIF function) can land first.

## Release note for the implementer
Commit as `ci(action): run Claude Code plugin audits from the ZIRAN GitHub Action` (the CLI part may
be a separate `feat(audit): write SARIF from ziran audit` commit; tests as `test(...)`). No `!`, no
`BREAKING CHANGE` footer (additive inputs/outputs/flag), no `Co-Authored-By` trailer. PR targets
`develop`, body links #420 and restates §3's contract summary for #423 / WUWEI #36.

## Phases
- P1 (tests first): `generate_audit_sarif` (FR-002).
- P2 (tests first): `ziran audit --sarif` (FR-001), sample plugin + baseline (FR-007).
- P3 (contract test first): `action.yml` (FR-003..FR-005).
- P4 (CI job is the test): `action-test.yml` job, example workflow, lint list (FR-006, FR-008).
- P5: docs (FR-009).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%); push and watch `Action Self-Test` + `Lint CI Templates` with
  `gh pr checks`. Do not commit `uv.lock` drift.

## Complexity Tracking
None.

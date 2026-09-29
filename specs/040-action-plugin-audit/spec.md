# Feature Specification: run Claude Code plugin audits from the ZIRAN GitHub Action

**Feature Branch**: `040-action-plugin-audit`
**Created**: 2026-09-29
**Status**: Active
**Issue**: #420 (part of epic #415). **Depends on**: #419 / spec `039-audit-allowlist-baseline`
(branch `039-audit-allowlist-baseline`, binding contract in its `plan.md` §Public contract:
`ziran audit --baseline FILE` / `--write-baseline FILE`, critical `BL001`..`BL004` rows, exit
`0`/`1`/`2`), which builds on #418 / spec `038-audit-claude-code-plugins` (merged to `develop` as
9a045b1: `audit_claude_code`, `StaticFinding.agent` / `.tools`, JSON rows
`{rule, severity, file, line, message, agent, tools}`).
**Consumers**: #423 (guide; links the action inputs and the example workflow below).
**Downstream**: WUWEI #36 runs this action in audit mode over its `agents/` directory with a
committed allowlist baseline; a PR that widens an agent must fail the build naming the chain it
creates. WUWEI pins the release and writes against the action inputs/outputs, the `--sarif` flag
and the exit codes below, so they are a stable contract.
**Input**: `action.yml` already routes `command: audit` to `ziran audit <source-path> --severity
<severity-threshold>`, but it cannot pass a baseline, `ziran audit` cannot write SARIF (only
`ziran ci --sarif` can, and only for campaign results), so the action's existing SARIF upload
never runs for audits, and the step reports every non-zero exit as `status=failed` with no way to
tell "widened" (exit `1`) from "misconfigured" (exit `2`). The only CI coverage of the action
(`.github/workflows/action-test.yml`) runs the released `taoq-ai/ziran@v0`, so a change to
`action.yml` is never exercised before release.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A widened agent fails the plugin repo's build and lands in the Security tab (Priority: P1)
A plugin maintainer copies the example workflow, commits `ziran-baseline.json` (recorded with
`ziran audit . --write-baseline ziran-baseline.json`), and pushes a PR that adds `WebFetch` to the
`builder` agent. The ZIRAN step fails, its log names the agent, the tool and the new chain, and the
findings appear in the repository's code scanning alerts.

**Why this priority**: The issue's acceptance criterion and WUWEI #36's.

**Independent Test**: A new job in `.github/workflows/action-test.yml` runs the action from the
checkout (`uses: ./`, `ziran-version: "."`) over a widened copy of the sample plugin in
`examples/07-cicd-quality-gate/claude-code-plugin/`, and asserts the step outcome, the outputs and
the SARIF content. The same scenario runs locally through `CliRunner` in the unit tests.

**Acceptance Scenarios**:
1. **Given** the sample plugin copied to `widened-plugin/` with `, WebFetch` appended to the
   `tools:` line (line 4) of `agents/builder.md`, **When** the action runs with
   `command: audit`, `path: widened-plugin`, `baseline: widened-plugin/ziran-baseline.json`,
   `sarif-output: ziran-audit.sarif`, **Then** the step fails (`outcome == failure`), outputs
   `status == failed`, `exit-code == 1`, `sarif-file == ziran-audit.sarif`.
2. **Given** the same run, **Then** `ziran-audit.sarif` is SARIF 2.1.0 with a result
   `ruleId == "BL001"`, `level == "error"`, message
   `"Agent 'builder' gains tool 'WebFetch' not in the baseline"`, location uri
   `widened-plugin/agents/builder.md` with `region.startLine == 4`, and a result
   `ruleId == "BL003"` whose message is
   `"Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch not in the baseline"`.
3. **Given** the same run on a push to `develop` or a PR from a branch of this repository (not a
   fork, not Dependabot), **Then** the action's SARIF upload ran and output a non-empty `sarif-id`.
4. **Given** the same change, **When** `ziran audit widened --baseline B --sarif out.sarif` runs
   under `CliRunner`, **Then** the exit code is `1` and `out.sarif` holds the same `BL001` and
   `BL003` results (locations relative to the working directory).

### User Story 2 — An unchanged plugin passes (Priority: P1)
**Acceptance Scenarios**:
1. **Given** the sample plugin and its committed baseline, **When** the action runs with
   `path` and `baseline` set and `sarif-output: ""`, **Then** the step succeeds, `status ==
   passed`, `exit-code == 0`.
2. **Given** the committed `ziran-baseline.json` of the sample plugin, **Then** it is
   byte-identical to what `ziran audit <sample> --write-baseline` writes on the current code (the
   sample never drifts from the chain patterns silently), and `ziran audit <sample> --baseline
   <file> --format json` exits `0` with `findings == []`.

### User Story 3 — Misconfiguration is distinguishable from findings (Priority: P1)
WUWEI maps exit `1` to "widened or failing findings" and `2` to "could not run".

**Acceptance Scenarios**:
1. **Given** `baseline` pointing to a file that does not exist, **When** the action runs, **Then**
   the step fails, `exit-code == 2`, `status == failed`, and the log carries an `::error::`
   annotation saying the audit could not run.
2. **Given** `ziran audit PATH --sarif DIR/x.sarif` where `DIR` does not exist, **Then** the exit
   code is `2` and no traceback is printed.

### User Story 4 — SARIF for any audit (Priority: P2)
**Acceptance Scenarios**:
1. **Given** any `ziran audit` run with `--sarif F` (text or JSON, with or without a baseline, with
   or without Claude Code agents), **Then** `F` is written before the command exits and holds
   exactly the rows the run reports (after the baseline step and `--severity`), one SARIF result
   per row, in report order; zero rows give a valid document with `results == []` (so an upload
   closes fixed alerts).
2. **Given** `--format json --sarif F`, **Then** stdout is still exactly the JSON document (the
   "SARIF written" notice goes to stderr) and the JSON document is unchanged.
3. **Given** a Python finding whose `context` holds a secret, **Then** the SARIF file does not
   contain the `context` value (same explicit-keys rule as the JSON output).
4. **Given** a `--baseline` run that reports narrowings, **Then** the SARIF has no entry for them
   (they are not findings; #419 §4).

### Edge Cases
- `path` and `source-path` both set: `path` wins. `path` empty (default): `source-path` (default
  `.`) is used, so existing workflows keep working unchanged.
- `baseline` set with `command` other than `audit`: ignored (the other commands never read it).
- `sarif-output` default is `ziran-results.sarif`, so existing `command: audit` workflows now also
  write and upload SARIF. The upload step is `continue-on-error: true` (unchanged), so a workflow
  without `security-events: write` still gets the audit's own pass/fail.
- Paths with spaces in `path`, `baseline`, `sarif-output` work (inputs reach bash through `env`, quoted).
- Absolute finding paths under the working directory are written relative to it in SARIF; paths
  outside it are written as `file://` URIs. Relative paths are written in POSIX form with
  `uriBaseId: "%SRCROOT%"`.
- A finding without a line number has no `region`.
- A rule id reported at several severities (e.g. `CC001` without a baseline) gets the highest one as
  its rule-level `security-severity`; each result keeps its own `level`.
- `severity-threshold` (default `low`) filters what is reported and uploaded. In the action's text
  mode the step fails on any `critical` row; with a baseline every widening is `critical`, so a
  widening fails under every threshold.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (`--sarif`)**: `ziran audit` MUST accept `--sarif FILE`, write a SARIF v2.1.0 document of
  the reported rows to it in every `--format`, after the `--severity` filter and before any output
  or exit, and exit `2` (Click `BadParameter`, no traceback) when the file cannot be written. Exit
  codes are otherwise unchanged (spec 036/038/039 rules).
- **FR-002 (SARIF mapping)**: one result per row: `ruleId` = rule, `level` from severity
  (`critical`/`high` -> `error`, `medium` -> `warning`, `low` -> `note`), `message.text` = the
  row's message, one physical location (uri per Edge Cases, `region.startLine` = line when set),
  and `properties` `{"agent", "tools"}` when the row has an agent. One rule per distinct rule id
  (first-seen order) with `shortDescription` = rule id, `help` = the first non-empty
  recommendation, and `properties.security-severity` from the highest severity seen (`critical`
  9.0, `high` 7.0, `medium` 5.0, `low` 3.0). Never the row's `context`. `BL001`..`BL004` need no
  special case.
- **FR-003 (action inputs)**: `action.yml` MUST gain inputs `path` (default `""`; audit target,
  wins over `source-path`) and `baseline` (default `""`; passed as `--baseline`), and the `audit`
  branch MUST pass `--sarif <sarif-output>` when `sarif-output` is non-empty. All existing inputs,
  defaults and the `scan`/`ci`/`policy` branches stay unchanged.
- **FR-004 (action outputs)**: `action.yml` MUST gain outputs `exit-code` (the ziran process exit
  code, every command) and `sarif-id` (the upload's id; empty when not uploaded). `status`,
  `trust-score`, `total-findings`, `critical-findings`, `sarif-file` stay unchanged. On audit exit
  `2` the step emits `::error::ziran audit could not run (exit 2): check the path, baseline and
  severity-threshold inputs`. The step exits with ziran's exit code.
- **FR-005 (no injection)**: the new and touched audit inputs reach the script through `env:` and
  are expanded quoted into a bash array; the audit branch never interpolates `${{ inputs.* }}` into
  the script body.
- **FR-006 (example)**: `examples/07-cicd-quality-gate/claude-code-audit.yml` MUST be a complete
  workflow for a plugin repository (checkout, `taoq-ai/ziran@v0` with `command: audit`, `path`,
  `baseline`, pinned `ziran-version`, permissions for SARIF upload) with the record / commit /
  re-record commands in comments, and MUST be linted by `lint-ci-templates.yml`.
- **FR-007 (sample plugin)**: `examples/07-cicd-quality-gate/claude-code-plugin/` MUST hold a
  minimal plugin (`.claude-plugin/plugin.json`, `agents/builder.md` with the WUWEI builder tools
  `Read, Glob, Grep, Bash, Write, Edit` on line 4, `agents/researcher.md` with `Read, Grep, Glob`)
  and its committed `ziran-baseline.json`, and no content that triggers any non-accepted finding.
- **FR-008 (CI acceptance)**: `.github/workflows/action-test.yml` MUST gain a job that runs the
  action from the checkout over the sample plugin and covers US1.1-3, US2.1 and US3.1, with no
  network beyond GitHub and the package index the action already installs from. Its `paths`
  filters MUST include `examples/07-cicd-quality-gate/claude-code-plugin/**`.
- **FR-009 (docs)**: `docs/guides/ci-integrations.md` MUST document the audit inputs, the new
  outputs, the exit codes and link the example; `docs/reference/cli.md` MUST list `--sarif` for
  `ziran audit`; `examples/07-cicd-quality-gate/README.md` MUST list the new files.

### Key Entities
- **Audit SARIF document**: SARIF 2.1.0 envelope identical to `ziran ci --sarif` (driver `ZIRAN`),
  results from `StaticFinding` rows.
- **Action contract**: inputs `command`, `path`, `source-path`, `baseline`, `severity-threshold`,
  `sarif-output`, `ziran-version`; outputs `status`, `exit-code`, `sarif-file`, `sarif-id`.

## Success Criteria *(mandatory)*
- **SC-001**: The new action-test job fails the widened run with `exit-code == 1`, a SARIF file
  carrying `BL001` (WebFetch, line 4) and `BL003` (`Read -> WebFetch`), and a non-empty `sarif-id`
  on same-repo runs.
- **SC-002**: The unchanged sample passes with `exit-code == 0`; a missing baseline gives `2`.
- **SC-003**: All quality gates pass; coverage stays >= 85%; no new runtime dependency.

## Assumptions
- #419 is merged to `develop` before the CLI part is implemented (it owns `--baseline`); the SARIF
  function does not depend on it.
- "Without network beyond GitHub itself" means the audit and the assertions make no network call;
  installing the package (`pip install .` from the checkout, like every existing action job) and
  the SARIF upload to GitHub are the only network use.
- The existing `test-ci-command` / `test-audit-command` jobs keep exercising the released `@v0`;
  only the new job runs the checkout's `action.yml`.
- The sample alerts uploaded by the CI job appear in this repository's code scanning under that
  job's category, like the existing `test-ci-command` job's alerts do.
- The example lives in `examples/07-cicd-quality-gate/` (the CI template folder) so it does not take
  an example number #423 may use for its runnable plugin example.
- The text-mode exit rule (fail on a `critical` row) is unchanged; the action does not switch audit
  to `--format json`.

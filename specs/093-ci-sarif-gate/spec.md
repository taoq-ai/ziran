# Feature Specification: `ziran ci` gates a ziran SARIF file

**Feature Branch**: `feat/093-ci-sarif-gate`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: A-CI-SARIF-GATE (goal G-b).
**Base**: `develop` @ 2988b9a (spec 092 merged: every chain in the scan SARIF).

## The promise in our own words

`ziran ci <file>` gates only a `CampaignResult` JSON. A pipeline that keeps only the scan's SARIF
(the standard contract code scanning reads) cannot gate on it. After this change:

1. `ziran ci` reads a SARIF 2.1.0 file that `generate_sarif` wrote and gates it with the same
   `QualityGate` rules: severity counts from the results, the trust score from the run's
   properties. `generate_sarif` now writes those properties.
2. A `CampaignResult` and the SARIF written from it give the same pass or fail, the same
   violations, the same counts and the same suppression states, with the same gate config and
   the same suppressions file.
3. A `CampaignResult` file still works unchanged.
4. A SARIF from another tool (no ziran run properties) exits non-zero with a message that names
   the missing properties. No traceback.
5. The GitHub Action's `command: ci` takes a `.sarif` `result-file`; the Action Self-Test gates
   one.

## User Scenarios & Testing

### User Story 1 - Gate a scan's SARIF in CI (P1)

1. **Given** a `CampaignResult` and the SARIF `generate_sarif` writes from it, **When**
   `ziran ci` runs on each with the same gate config, **Then** both give the same exit code,
   status, violations and finding counts.
2. **Given** a suppressions file, **When** both are gated, **Then** the same findings are new,
   suppressed or regressed, and the policy rule gives the same message.

### User Story 2 - A foreign SARIF fails clearly (P1)

1. **Given** a SARIF from another tool, or a `ziran audit` SARIF, **When** `ziran ci` runs,
   **Then** it exits 1 and names `target_agent`, `final_trust_score` and `success` as missing
   from `runs[0].properties.ziran`.
2. **Given** a SARIF with no run, two runs, or a result that is not an object, **Then** it exits
   1 with an error, not a traceback.

### User Story 3 - The Action gates a SARIF (P1)

1. **Given** the action with `command: ci` and `result-file: <scan>.sarif`, **When** the Action
   Self-Test runs, **Then** it gates the SARIF with the same status and counts as the JSON it
   came from.

### Edge cases

- Critical and high both map to SARIF level `error`, so the level cannot carry the severity. Each
  result carries its exact severity in `properties.severity`.
- A severity outside the four (for example `info`): the gate ignores it for a JSON; the SARIF
  keeps the raw value, so the gate ignores it there too.
- A SARIF written by `ziran ci --sarif` marks suppressed results; the gate ignores those marks and
  classifies again from the suppressions file.

## Requirements

- **FR-001**: `generate_sarif` writes `runs[0].properties.ziran` with `campaign_id`,
  `target_agent`, `final_trust_score`, `success`, `critical_paths`, `phase_vulnerabilities`
  (phase to its vulnerability ids, phases with findings only) and `metadata` (the unmeasured and
  warnings keys, when present).
- **FR-002**: Each attack and chain result carries `properties.severity`, the raw severity the
  gate reads (`severity` of the attack, `risk_level` of the chain, default `medium`). A chain
  result carries `properties.graph_path` when the chain has one.
- **FR-003**: `campaign_from_sarif(doc)` rebuilds the `CampaignResult` fields the gate reads:
  attacks from results without `vulnerability_type` (vector id, name, category and OWASP tags
  from the rule), chains from results with it, in result order.
- **FR-004**: `campaign_from_sarif` raises `ValueError` naming each missing required property,
  or the shape problem, for any other input.
- **FR-005**: `ziran ci` treats a JSON object with a `runs` key as SARIF; anything else loads as
  a `CampaignResult` as before.
- **FR-006**: The action's `result-file` input documents SARIF; the self-test gates a SARIF.

## How this fails

1. A new gate input is added to `QualityGate` but not to the run properties: the SARIF gate
   drifts. The parity test over gate configs and suppressions catches a field the gate reads.
2. Rule dedup: two results of one vector with different categories. The rule keeps the first.
   Vector category is fixed per vector, so this does not occur in a scan.
3. Someone hand-edits a SARIF: it is a gate input like the JSON and carries the same trust.

## Assumptions

- Severity lives in `properties.severity` per result, not only in level or `security-severity`.
  Why: level `error` is both critical and high, and the gate counts them apart. Overturned by: a
  standard SARIF field that holds the four values exactly.
- One run per SARIF. Why: `generate_sarif` writes one. Overturned by: merged multi-run files.
- `--sarif` with a SARIF input writes a new SARIF from the rebuilt result; it keeps the gate
  fields but drops messages, evidence and blast radius. Why: the gate is the goal; rewriting is
  a side path. Overturned by: a need to re-emit SARIF with full fidelity.
- Additive SARIF properties are a minor change (`feat:`). Overturned by: a consumer that rejects
  unknown properties.

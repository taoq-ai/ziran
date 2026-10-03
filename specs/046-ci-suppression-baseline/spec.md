# Feature Specification: CI finding suppression baseline and regression gate (accept / suppress / regress)

**Feature Branch**: `046-ci-suppression-baseline`
**Created**: 2026-10-03
**Status**: Active
**Issue**: #395 (batch "gates you can leave on", release 0.41.0).
**Siblings (parallel, other agents)**: #447 / spec 045 (`mcp_metadata_analyzer.py` only), #399 /
spec 047 (`ziran scan` + `_display_results` in `main.py`, LLM infra), #217 / spec 048
(`html_report.py` only). The only shared file is `ziran/interfaces/cli/main.py`; this feature edits
only the `ci` command and `_display_gate_result`.
**Not in scope**: a `--write-suppressions` generator, UI/DB status sync, `ziran audit` baselines
(spec 039 owns those), `action.yml` inputs or outputs, fingerprinting of `critical_paths`, the
`--policy` overlay of `ziran ci` (it is displayed only and never sets the exit code).
**Input**: `ziran ci` (`ziran/application/cicd/gate.py`) fails a build on findings above a
severity threshold. A reviewed, accepted finding cannot be accepted individually: teams mute the
whole gate or re-triage on every run. CI runs are stateless and file-driven, so the acceptance
record has to be a committed file.

## User Scenarios & Testing *(mandatory)*

Shared fixture vocabulary (used by every scenario): a `CampaignResult` with
`target_agent="test_agent"`, one successful attack result `A` (`vector_id="v1"`,
`category="prompt_injection"`, `severity="critical"`) and one dangerous tool chain `C`
(`vulnerability_type="data_exfiltration"`, `tools=["read_file", "http_request"]`,
`risk_level="critical"`). `fp(A)`, `hash(A)`, `fp(C)`, `hash(C)` are the values defined in FR-002 /
FR-003. "Default config" is `QualityGateConfig()` (critical threshold 0, `max_critical_findings`
0, `fail_on_policy_violation` true).

### User Story 1 — Accept a reviewed finding (Priority: P1)
An operator lists a finding in `.ziran/suppressions.yaml` with a reason and owner; the gate no
longer fails on it and the summary reports it as suppressed.

**Why this priority**: The core ask of the issue; without it the gate cannot be left on.

**Independent Test**: `QualityGate().evaluate(result, suppressions)` with stub data, no scan.

**Acceptance Scenarios**:
1. **Given** a result containing only `A` and a suppressions file with one entry
   `{fingerprint: fp(A), content_hash: hash(A), reason: "accepted risk", added_by: "sec-team"}`,
   **When** the gate evaluates with the default config, **Then** `A` is classified `suppressed`,
   `finding_counts.critical == 0`, `suppressed_findings == 1`, `new_findings == 0`,
   `regressed_findings == 0`, no `max_critical_findings` / `severity_threshold_critical`
   violation is raised, and `summary` contains `Suppressions: new 0, suppressed 1, regressed 0`.
2. **Given** the same for chain `C` (entry `fp(C)` / `hash(C)`), **Then** `C` is `suppressed` and
   does not count toward any threshold.
3. **Given** a result with `A`, `C`, `critical_paths=[["cap_x", "v1"], ["read_file",
   "composition::data_exfiltration::read_file->http_request"]]`, one phase with
   `vulnerabilities_found=["v1"]`, `success=True`, and entries for both, **When** evaluated with
   the default config, **Then** the gate PASSES (exit code 0): no `policy_violation` (FR-008), no
   threshold violation.
4. **Given** an entry whose `expires` is today or later, **Then** it still suppresses.

### User Story 2 — A materially changed finding regresses and fails (Priority: P1)
**Why this priority**: Issue acceptance criterion: a suppressed finding must not stay silently
suppressed after it changes.

**Acceptance Scenarios**:
1. **Given** the US1.2 entry for `C` and a result where `C`'s tools became `["read_file",
   "send_email"]` (same `vulnerability_type`, so same fingerprint, different content hash), **When**
   evaluated, **Then** `C` is `regressed`, `regressed_findings == 1`, it counts toward the severity
   thresholds (critical 1), a violation `rule="suppression_regressed"` whose message contains
   `fp(C)` is raised, and the gate FAILS.
2. **Given** the US1.1 entry for `A` and `A`'s severity changed to `high`, **Then** `A` is
   `regressed` and the gate fails with `suppression_regressed` naming `fp(A)`.
3. **Given** `C`'s `risk_level` changed, **Then** `C` is `regressed`.
4. **Given** only `evidence` (including `evidence["tool_calls"]`), `agent_response`, `prompt_used`
   or `vector_name` of `A` changed, **Then** `A` stays `suppressed` (cosmetic or LLM-flapping
   fields are not hashed).
5. **Given** `A`'s `category` changed, **Then** `A` has a different fingerprint and is `new`
   (category is part of the attack identity, FR-002).

### User Story 3 — Expired acceptances fail with a clear message (Priority: P1)
**Acceptance Scenarios**:
1. **Given** the US1.1 entry with `expires: 2026-01-01` and `today=2026-01-02`, **When** evaluated,
   **Then** the entry does not suppress (`A` is `new`, counted, fails the critical threshold), and
   a violation `rule="suppression_expired"` whose message contains `fp(A)` and `2026-01-01` is
   raised.
2. **Given** an expired entry that matches no finding in the result, **Then** the gate still fails
   with `suppression_expired` naming that entry's fingerprint (expired entries must be renewed or
   removed).

### User Story 4 — New findings still fail as before (Priority: P1)
**Acceptance Scenarios**:
1. **Given** a suppressions file with an entry for `A` and a result containing `A` plus a second
   successful critical attack `B` (`vector_id="v2"`), **When** evaluated with the default config,
   **Then** `B` is `new`, `new_findings == 1`, `suppressed_findings == 1`, `finding_counts.critical
   == 1`, and the gate fails on `max_critical_findings` and `severity_threshold_critical`.
2. **Given** the US4.1 run through `ziran ci`, **Then** stdout contains one line per unsuppressed
   finding with its state, kind, label, severity, full `fingerprint=` and `content_hash=` values
   (FR-012), so the operator can copy them into an entry.

### User Story 5 — No suppressions file means no change at all (Priority: P1)
**Why this priority**: Every existing pipeline must behave byte-identically.

**Acceptance Scenarios**:
1. **Given** no `.ziran/suppressions.yaml` in the working directory and no `--suppressions` flag,
   **When** `ziran ci` runs on any result, **Then** the exit code, stdout, SARIF file, step-summary
   file and `$GITHUB_OUTPUT` lines are byte-identical to `develop` before this feature (proven
   against outputs captured on `origin/develop`), and every existing test passes unmodified.
2. **Given** `QualityGate().evaluate(result)` (no suppressions argument), **Then** `status`,
   `violations`, `finding_counts`, `trust_score` and `summary` equal today's for the existing
   `tests/unit/test_cicd.py` fixtures.

### User Story 6 — Code scanning and GitHub UIs render suppressions correctly (Priority: P2)
**Acceptance Scenarios**:
1. **Given** a run with `A` suppressed and `B` new and `--sarif out.sarif`, **Then** the SARIF
   result for `A` has `"suppressions": [{"kind": "external", "justification": "accepted risk"}]`
   and the result for `B` has no `suppressions` key.
2. **Given** the same run, **Then** `emit_annotations` emits no annotation for `A` and one for
   `B`, and `write_step_summary` omits `A` from "Vulnerabilities Found", shows a "Suppressions"
   table with the three counts, and its severity table reflects new + regressed only.
3. **Given** the same run in GitHub Actions, **Then** `$GITHUB_OUTPUT` additionally receives
   `new_findings=1`, `suppressed_findings=1`, `regressed_findings=0`.

### User Story 7 — File location and override (Priority: P2)
**Acceptance Scenarios**:
1. **Given** `.ziran/suppressions.yaml` in the current working directory, **When** `ziran ci`
   runs without `--suppressions`, **Then** the file is loaded.
2. **Given** `--suppressions other.yaml`, **Then** that file is loaded instead and the cwd file is
   ignored.
3. **Given** `--suppressions missing.yaml` (path does not exist), **Then** click rejects it (exit
   2, usage error).
4. **Given** a suppressions file that is not a mapping, has `version` other than `1`, an unknown
   key, an entry missing `reason` or `added_by`, an empty `reason`, a `fingerprint` or
   `content_hash` that is not 64 lowercase hex characters, or an invalid `expires`, **Then**
   `ziran ci` prints `Error loading suppressions: ...` and exits 1 (never silently ignores a
   malformed acceptance record, including the auto-loaded one).

### Edge Cases
- Several findings may share one fingerprint (two `data_exfiltration` chains with different
  tools; one vector reported twice). An entry list may hold the same fingerprint several times
  with different content hashes: a finding is suppressed when **any** non-expired entry matches
  both its fingerprint and its content hash. A finding whose fingerprint matches a non-expired
  entry but whose content hash matches none is `regressed` (fail-closed).
- Entries that match no finding (stale) are ignored without a violation, unless expired (US3.2).
- A finding whose only matching entries are expired is `new`, not `regressed`; the expiry itself
  is reported by `suppression_expired`.
- Unsuccessful attack results are not findings and are never classified.
- A severity outside `low|medium|high|critical` (e.g. `info`) is classified and counted in the
  three state counts, but not in `finding_counts` (unchanged from today).
- `finding_counts`, `total_findings` and `critical_findings` exclude suppressed findings when a
  file is loaded.
- A critical path ending at a `DATA_SOURCE` node (e.g. `sensitive_data`, added for dangerous
  capabilities) is never backed by a finding, so with `fail_on_policy_violation: true` such an
  agent still fails `policy_violation` even when every finding is suppressed. This is today's
  behaviour for those agents (their `success` is always true); critical-path fingerprinting is out
  of scope. Operators set `fail_on_policy_violation: false` to rely on findings only.
- Fingerprints of attack results use the same function as the web findings page
  (`findings_extractor`), so the same `target_agent` / `vector_id` / `category` yield the same
  fingerprint in both places.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (file model)**: `ziran/domain/entities/ci.py` gains `SuppressionEntry`
  (`fingerprint`, `content_hash`, `reason`, `added_by`, optional `expires: date`) and
  `SuppressionFile` (`version: Literal[1]`, `entries: list[SuppressionEntry]`, default empty).
  Both forbid unknown keys; `fingerprint` and `content_hash` must match `^[0-9a-f]{64}$`; `reason`
  and `added_by` must be non-empty.
- **FR-002 (attack fingerprint)**: a pure domain function computes the attack-result fingerprint
  from `target_agent`, `vector_id`, `category` (SHA-256 of `"{target_agent}:{vector_id}:{category}"`,
  64 hex). It is the logic of today's `findings_extractor._compute_fingerprint`, moved to the
  domain; `findings_extractor` imports it (no second copy). Tool calls are NOT part of the key.
- **FR-003 (chain fingerprint)**: dangerous tool chains are keyed on `target_agent` +
  `vulnerability_type` only (the tools list is NOT part of the key, so a changed chain regresses
  instead of appearing new).
- **FR-004 (content hash)**: attack results hash `severity` + `category`; chains hash the ordered
  `tools` list + `risk_level`. Hashes are SHA-256 over canonical JSON (sorted keys, no whitespace).
  `evidence` (in particular `evidence["tool_calls"]`, which comes from the LLM and flaps between
  runs), `agent_response`, `prompt_used`, names and descriptions are never hashed.
- **FR-005 (classification)**: with a suppressions file, every successful attack result and every
  dangerous tool chain is classified `suppressed`, `regressed` or `new` per the Edge Cases rules.
  An entry is expired when `expires < today` (valid through its `expires` date).
- **FR-006 (counts)**: severity thresholds and `max_critical_findings` count new + regressed
  findings only. `GateResult` gains `new_findings`, `suppressed_findings`, `regressed_findings`,
  the classified `findings` list and `suppressions_applied`.
- **FR-007 (violations)**: one `suppression_regressed` violation per regressed finding and one
  `suppression_expired` violation per expired entry; each message names the entry's fingerprint.
- **FR-008 (policy violation, explicit rule)**: when a suppressions file is loaded and
  `fail_on_policy_violation` is true, `policy_violation` is raised iff at least one of:
  (a) there is an unsuppressed finding (new or regressed);
  (b) some `critical_paths` entry ends at a node that is not *backed*;
  (c) some vector id in any phase's `vulnerabilities_found` is not *backed*.
  A node is *backed* iff it is the `vector_id` of a suppressed attack result, or the composition
  node id (`composition::{vulnerability_type}::{"->".join(tools)}`, as built by
  `AttackKnowledgeGraph.add_chain_finding`) of a suppressed chain. Without a suppressions file the
  check is today's `result.success` rule, unchanged.
- **FR-009 (file loading)**: `ziran ci` loads `--suppressions PATH` when given, else
  `.ziran/suppressions.yaml` relative to the current working directory when it exists, else
  nothing. Any load/validation error exits 1 with `Error loading suppressions: <detail>`.
- **FR-010 (SARIF)**: SARIF results of suppressed attack results carry
  `"suppressions": [{"kind": "external", "justification": <entry reason>}]`. Nothing else in SARIF
  changes.
- **FR-011 (GitHub Actions)**: `emit_annotations` and the "Vulnerabilities Found" table of
  `write_step_summary` skip suppressed attack results; when a file is loaded the step summary adds
  a "Suppressions" table and `ziran ci` writes the `new_findings`, `suppressed_findings`,
  `regressed_findings` outputs.
- **FR-012 (operator output)**: when a file is loaded, `ziran ci` prints the three counts and one
  unwrapped line per new or regressed finding with its full fingerprint and content hash.
- **FR-013 (absent = unchanged)**: without a suppressions file, outputs and exit codes are
  byte-identical to today (US5).
- **FR-014 (docs)**: `docs/guides/cicd-integration.md` gains a `## Suppressing Accepted Findings`
  section (file format, fingerprint/content-hash semantics, regression, expiry, the FR-008 rule and
  the data-source limitation, bootstrap with an empty file); `docs/reference/cli.md` gains the
  `--suppressions` row under `ziran ci`. Every example output comes from a command actually run.

### Assumptions (recorded, most conservative reading)
- The issue's "fingerprint (vector id + tool-chain signature + target)" is narrowed by the release
  planner: the tool chain is in the **content hash**, not the key, so that "changing that
  finding's tool chain flips it to regressed" holds. For dangerous tool chains this is literal; for
  attack results the issue's "new evidence" is not hashed because `evidence["tool_calls"]` is
  LLM-produced and would make every suppression flap.
- "An expired entry fails the gate" applies to every expired entry, matched or not (US3.2).
- Fingerprint lines are printed only when a suppressions file is loaded (FR-013 forbids new output
  otherwise). Bootstrap: commit `version: 1` with no entries, run `ziran ci`, copy the printed
  values.
- An explicit `--suppressions` path that does not exist is a usage error (a typo must not
  silently disable suppressions); a missing auto-load file is not an error.
- With a file loaded, FR-008 can fail a run that `result.success` would have passed (an
  unsuppressed non-critical chain on a trace-analysis result): stricter, never looser, than today.
- `today` is the local date of the CI runner (`date.today()`), injectable for tests.
- The violations' `severity` is `"high"` for both new rules (a label only; counting is unchanged).
- The composite `action.yml` runs `ziran ci` in the workspace root, so the committed file is
  auto-loaded there; declaring the three new outputs in `action.yml` is out of scope (follow-up).
- Stale (unmatched, unexpired) entries are not reported; YAGNI until asked.

### Key Entities
- **SuppressionEntry** / **SuppressionFile**: the committed acceptance record (FR-001).
- **GateFinding**: one classified finding (`kind`, `index`, `label`, `severity`, `fingerprint`,
  `content_hash`, `state`, `reason`), domain model in `ci.py`.
- **GateResult** (extended): three counts, `findings`, `suppressions_applied`.

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: US1-US4 and US6-US7 pass as unit tests in `tests/unit/test_cicd_suppressions.py`
  (suppress, regress via tool-chain change, regress via severity change, expire, new finding,
  absent file, all findings suppressed with the default config passing), offline, no network.
- **SC-002**: every pre-existing test passes unmodified (in particular `tests/unit/test_cicd.py`,
  `tests/unit/test_cli_main.py::TestCiCommand`, `tests/unit/test_findings_extractor.py`).
- **SC-003**: `ziran ci` outputs (stdout, SARIF, step summary, `$GITHUB_OUTPUT`, exit code) on the
  fixture results without a suppressions file are byte-identical to the same commands run on
  `origin/develop` (diff of captured files is empty).
- **SC-004**: all gates pass: ruff, ruff format, mypy strict, pytest coverage >= 85%; no new
  dependency; `uv.lock` unchanged; `tests/unit/application/test_scanner_size.py` unaffected.

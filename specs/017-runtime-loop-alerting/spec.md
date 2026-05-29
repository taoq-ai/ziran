# Feature Specification: Runtime Loop Alerting and Automation

**Feature Branch**: `017-runtime-loop-alerting`  
**Created**: 2026-05-29  
**Status**: Draft  
**Input**: User description: "Close the pre-deploy→runtime→observability feedback loop from the v0.8 runtime bridge (spec 011) by making three existing one-shot commands actively notify humans and repos: watch-registry alerting (#272), analyze-traces alerting (#274), and a policy-export auto-refresh GitHub Action (#273)."

## Overview

The v0.8 runtime bridge (spec 011) shipped three commands that each produce findings but stop at writing a file or printing to stdout: `watch-registry` (MCP drift detection), `analyze-traces` (production trace analysis), and `export-policy` (guardrail policy generation). A scheduled watcher, a trace analyzer, and a policy exporter only deliver value if their output reaches the humans and systems that can act on it. This feature closes the loop by routing findings to people (Slack), to tracking systems (GitHub issues), and to source control (policy-refresh pull requests) — with deduplication so repeated runs do not generate noise.

## Clarifications

### Session 2026-05-29

- Q: How should the GitHub issue sink know a finding was already filed (dedup mechanism)? → A: GitHub-side marker — embed the fingerprint as a hidden marker in the issue body and dedup by searching open + closed issues via the GitHub API (stateless; no local state file).
- Q: What composes the fingerprint for a registry drift finding? → A: `(server, tool, drift-kind)` — the same kind of drift on the same tool is one finding regardless of the specific new value.
- Q: What exit status should a run return when detection succeeds but at least one delivery fails? → A: A distinct non-zero exit code for partial delivery failure, separate from the fatal-crash code.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Registry drift reaches a human (Priority: P1)

A security engineer runs `watch-registry` on a schedule against production MCP servers. When the watcher detects drift — a newly added tool, a changed tool description, a permission escalation, or a suspected typosquat — the finding is delivered to a configured Slack channel and/or filed as a GitHub issue, instead of disappearing into a log file nobody reads.

**Why this priority**: This is the foundational slice. It introduces the shared notification capability (the "alert sink" concept) that the other stories reuse, and it delivers immediate standalone value: scheduled watchers become actionable. Without it, the other two stories have nothing to build on.

**Independent Test**: Configure a watcher with a Slack sink and a GitHub issue sink pointed at test endpoints, introduce a drift event in a mock registry snapshot, run the watcher, and confirm a correctly-formatted Slack message and a GitHub issue are produced. Re-run with no new drift and confirm nothing new is sent.

**Acceptance Scenarios**:

1. **Given** a watcher configured with a Slack sink and a drift event of severity at or above the sink's floor, **When** the watcher runs, **Then** a formatted message describing the drift (kind, server, before/after, severity) is delivered to the configured channel.
2. **Given** a watcher configured with a GitHub issue sink, **When** a new drift event is detected, **Then** an issue is opened in the configured repository with the configured labels, pre-filled context, and a link to the registry snapshot diff.
3. **Given** a drift event below a sink's configured severity floor, **When** the watcher runs, **Then** that sink does not emit anything for that event.
4. **Given** the same drift event has already produced a GitHub issue, **When** the watcher runs again, **Then** no duplicate issue is opened.
5. **Given** the operator passes a dry-run option, **When** the watcher runs, **Then** the system prints what each sink would send without contacting any external service.
6. **Given** a sink's credential is missing or the external service rejects the request, **When** the watcher runs, **Then** the failure is reported clearly and does not prevent other sinks or other findings from being processed.

---

### User Story 2 - Dangerous production behavior files a tracked issue (Priority: P2)

An operator runs `analyze-traces` against exported production traces (OTel JSONL or Langfuse). When a reconstructed tool-call sequence matches a dangerous chain that ZIRAN flagged during a pre-deploy scan, the system opens a GitHub issue routing the finding to whoever can fix it — including the observed tool sequence, the matching pre-deploy finding, the trace source link, the inherited severity, and suggested remediation when available.

**Why this priority**: This closes the observability half of the loop and reuses the notification capability from Story 1, so it is lower risk and naturally sequenced after P1. It depends on Story 1's sink concept existing.

**Independent Test**: Feed synthetic trace fixtures containing one novel dangerous-chain execution to the analyzer with a GitHub issue sink, and confirm exactly one issue is opened with the required content. Re-run on the same fixtures and confirm zero new issues.

**Acceptance Scenarios**:

1. **Given** a trace that matches a dangerous chain from a prior scan, **When** `analyze-traces` runs with a GitHub issue sink, **Then** an issue is opened containing the exact tool sequence, a link to the matching pre-deploy finding (and the existing issue if one exists), the session ID and trace source link, and the severity copied from the matched finding.
2. **Given** an exported policy bundle covers the matched chain, **When** the issue is filed, **Then** the issue includes the suggested remediation derived from that bundle.
3. **Given** the same dangerous chain in the same session has already been filed, **When** `analyze-traces` is re-run on the same traces, **Then** no duplicate issue is created.
4. **Given** the operator selects aggregated digest mode, **When** multiple dangerous chains are detected in a run, **Then** they are combined into a single periodic digest rather than one issue per session.

---

### User Story 3 - Exported policies stay fresh automatically (Priority: P3)

A platform team wires a reusable automation into their repository so that exported guardrail policies do not silently go stale as the attack library or target agent configuration changes. On a weekly schedule (or manual trigger), the automation re-scans the target, regenerates the policy bundle, and — if the generated policies differ from what is committed — opens or updates a pull request with the refreshed files for review.

**Why this priority**: This is valuable but independent of the sink work and the heaviest to validate end-to-end (it runs real commands in CI and manipulates pull requests), so it is sequenced last. It can ship separately without blocking Stories 1 and 2.

**Independent Test**: Run the automation against the bundled example agent in a test repository, confirm a pull request with regenerated policy files is opened when the committed bundle is stale, and confirm no pull request is opened when the bundle is already current.

**Acceptance Scenarios**:

1. **Given** the committed policy bundle is out of date relative to a fresh scan, **When** the automation runs, **Then** a pull request is opened (or the existing refresh PR is updated) with the regenerated policy files, labeled for policy refresh and assigned to a reviewer team.
2. **Given** the committed policy bundle already matches a fresh scan, **When** the automation runs, **Then** no pull request is created.
3. **Given** the team configures hard enforcement instead of pull requests, **When** the generated policies differ from the committed bundle, **Then** the automation fails the run so the difference blocks the pipeline.
4. **Given** the team scopes the automation to a subset of policy formats, **When** it runs, **Then** only the selected formats are regenerated and diffed.
5. **Given** either a squash or a merge-commit pull request strategy, **When** the refresh runs across iterations, **Then** it continues to update a single refresh pull request rather than spawning duplicates.

---

### Edge Cases

- **External service outage**: A sink endpoint is unreachable or returns an error — the run records the failure, continues with remaining sinks/findings, and exits with a status that signals partial delivery rather than silent success.
- **Missing credentials**: A configured sink has no available secret — the system reports the misconfiguration clearly before attempting delivery rather than failing mid-send.
- **Severity floor excludes everything**: All findings fall below every sink's floor — the run completes cleanly and reports that nothing was eligible to send.
- **Fingerprint collisions vs. genuine recurrence**: Two genuinely distinct findings must not share a fingerprint; the same finding recurring must reuse its fingerprint so it dedups.
- **Reopened/closed issues**: A previously filed issue was manually closed — re-detection must not silently reopen or spam; behavior here is defined in Assumptions.
- **Concurrent automation runs**: Two scheduled policy-refresh runs overlap — they must not open competing pull requests for the same refresh.
- **Empty inputs**: No registry snapshot history yet, or no traces in the input — the commands complete without error and emit nothing.
- **Dry-run with real credentials present**: Dry-run must never contact external services even when credentials are configured.

## Requirements *(mandatory)*

### Functional Requirements

#### Shared notification capability

- **FR-001**: The system MUST provide a single notification abstraction that accepts a finding and delivers it to an external destination, reusable across the registry watcher and the trace analyzer.
- **FR-002**: The system MUST support delivering findings to a Slack channel via webhook and to a GitHub repository as an issue.
- **FR-003**: The system MUST allow multiple notification destinations to be configured simultaneously, and MUST attempt delivery to every configured destination for each eligible finding.
- **FR-004**: Each notification destination MUST support a configurable minimum severity (severity floor); findings below the floor MUST NOT be delivered to that destination.
- **FR-005**: The system MUST source destination credentials (webhook URLs, access tokens) from environment variables, including via an `!env VAR_NAME` reference in YAML configuration, and MUST NOT require secrets to be written inline in committed configuration.
- **FR-006**: The GitHub issue destination MUST deduplicate by a stable finding fingerprint so that re-running does not open duplicate issues for the same finding. Deduplication MUST be stateless: the fingerprint is embedded as a hidden marker in the issue body, and the destination checks for an existing issue by searching open and closed issues via the GitHub API (no local dedup-state file).
- **FR-007**: The system MUST provide a dry-run mode that prints what each destination would send without contacting any external service.
- **FR-008**: A delivery failure to one destination MUST NOT prevent delivery attempts to other destinations or processing of other findings; failures MUST be surfaced to the operator. When detection succeeds but one or more deliveries fail, the run MUST exit with a distinct non-zero status code that is separate from the code used for a fatal/crash error, so schedulers can distinguish partial-delivery failures from hard failures.

#### Registry drift alerting (`watch-registry`)

- **FR-009**: The registry watcher MUST emit every detected drift finding (added tool, changed description, permission escalation, suspected typosquat) to each configured notification destination. A drift finding's dedup fingerprint MUST be composed of `(server, tool, drift-kind)`, so a recurring drift of the same kind on the same tool reuses one issue regardless of the specific changed value.
- **FR-010**: Slack drift messages MUST include the drift kind, affected server, the relevant before/after detail, and severity.
- **FR-011**: GitHub drift issues MUST include configured labels, pre-filled context, and a representation of the registry snapshot diff: a resolvable URL when one is available (e.g. a CI-published snapshot artifact), otherwise an inline diff summary (the changed before/after values) embedded directly in the issue body. A bare local filesystem path MUST NOT be used as the link, since it is not resolvable by a remote reader.
- **FR-012**: Notification configuration for the watcher MUST be expressible in YAML alongside the existing registry configuration.

#### Production trace alerting (`analyze-traces`)

- **FR-013**: When the trace analyzer identifies a dangerous-chain execution in production traces, it MUST be able to deliver that finding through the shared notification capability.
- **FR-014**: A trace-derived GitHub issue MUST include the observed tool sequence, a link to the matching pre-deploy finding (and to the existing issue for that finding if one exists, located via the same embedded-marker search used for deduplication), the session identifier, the trace source link (e.g., Langfuse URL or OTel trace identifier), and the severity copied from the matched pre-deploy finding.
- **FR-015**: When an exported policy bundle covers the matched chain, the issue MUST include the corresponding suggested remediation.
- **FR-016**: Trace findings MUST be deduplicated by a fingerprint combining the tool-chain identity and the session, so re-running on the same traces produces no new issues.
- **FR-017**: The trace analyzer MUST support both per-session issues and an aggregated periodic digest mode.

#### Policy-export automation (`export-policy`)

- **FR-018**: The system MUST provide a reusable repository automation that scans a configured target, regenerates the policy bundle, and compares the result against the committed bundle.
- **FR-019**: When the regenerated bundle differs from the committed bundle, the automation MUST open or update a single pull request containing the refreshed files, apply a policy-refresh label, and assign a reviewer team.
- **FR-020**: When the regenerated bundle matches the committed bundle, the automation MUST make no change and open no pull request.
- **FR-021**: The automation MUST support a hard-enforcement option that fails the run on any difference instead of opening a pull request.
- **FR-022**: The automation MUST support scoping to a subset of the supported policy formats (OPA/Rego, Cedar, NeMo Colang, Invariant Labs), defaulting to all formats.
- **FR-023**: The automation MUST support both scheduled (e.g., weekly) and manual invocation.
- **FR-024**: The automation MUST function under both squash and merge-commit pull request strategies without producing duplicate refresh pull requests.
- **FR-025**: The system MUST provide a documented, copyable workflow template demonstrating the automation.

#### Documentation

- **FR-026**: The trace-analysis guide MUST gain a section describing alerting configuration and behavior.
- **FR-027**: A new guide MUST document the policy-refresh automation end to end.

### Key Entities *(include if feature involves data)*

- **Finding**: A normalized unit of information eligible for delivery — carries a kind, a severity, descriptive context, and a stable fingerprint used for deduplication. The fingerprint is embedded as a hidden marker in any GitHub issue created for the finding. Specializations include a registry drift finding (fingerprint = `(server, tool, drift-kind)`) and a dangerous-chain trace finding (fingerprint = tool-chain identity + session).
- **Notification Destination**: A configured target that can receive findings (Slack channel via webhook, or GitHub repository as issues), with its own severity floor and credentials.
- **Drift Event**: A change between two registry snapshots (added tool, description change, permission escalation, suspected typosquat), with affected server and before/after detail.
- **Dangerous-Chain Match**: A reconstructed production tool-call sequence that matches a pre-deploy finding, carrying the session identity, trace source link, inherited severity, and optional remediation reference.
- **Policy Bundle**: The set of exported guardrail policy files (across one or more formats) that the automation compares against the committed version to decide whether a refresh is needed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A drift event detected by the watcher reaches every configured destination at or above its severity floor in a single run, with zero manual steps after configuration.
- **SC-002**: Re-running the watcher or the trace analyzer sequentially on unchanged input produces zero duplicate GitHub issues. Deduplication is best-effort under concurrent runs (the GitHub search index is eventually consistent); strict no-duplicate guarantees apply to sequential re-runs, not to two runs racing within the index-propagation window.
- **SC-003**: A dangerous-chain match in production traces results in a tracked issue containing all required context (tool sequence, matched finding link, session, trace link, severity) in 100% of matches.
- **SC-004**: When the committed policy bundle is stale, the automation surfaces the difference as a reviewable pull request (or a failed run under hard enforcement) on every scheduled run, and produces no pull request when the bundle is current.
- **SC-005**: A failure delivering to one destination never blocks delivery to other destinations or processing of other findings, and is always reported to the operator.
- **SC-006**: No secret value is ever required in committed configuration; all credentials resolve from the environment.
- **SC-007**: Dry-run mode contacts zero external services while still showing the operator exactly what would be sent.

## Assumptions

- **Reused commands**: `watch-registry`, `analyze-traces`, and `export-policy` already exist (shipped in the v0.8 runtime bridge, spec 011) and produce the findings this feature routes; this feature adds delivery and automation, not the underlying detection.
- **Scope boundary**: The NeMo Guardrails DefenceProfile evaluator (issue #271) is explicitly out of scope — it has been moved to the Ziran Cloud repository. Where this feature mentions NeMo Colang, that refers only to the existing policy-export output format, not a guardrail evaluator.
- **Closed/reopened issues**: Deduplication searches both open and closed issues for the embedded fingerprint marker; a manually closed issue is treated as already-filed and is not reopened. This conservative default avoids spam and can be revisited.
- **GitHub as the issue backend**: "Issue" destinations target GitHub repositories; other trackers are out of scope for this release.
- **Severity model**: Findings carry a severity comparable against a configured floor using the project's existing severity ordering; no new severity scheme is introduced.
- **Digest cadence**: Aggregated digest mode groups findings per analyzer run (treated as the digest window); a finer-grained scheduler is out of scope. The digest's dedup fingerprint is derived solely from the set of contained chain fingerprints (NOT the run date), so re-running on unchanged traces — even on a later day — reuses the same digest issue rather than filing a new one, consistent with SC-002.
- **Single refresh PR**: The policy-refresh automation maintains one long-lived refresh pull request per repository/target, identified by a stable branch or marker, rather than one PR per run.

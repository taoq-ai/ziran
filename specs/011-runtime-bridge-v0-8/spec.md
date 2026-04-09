# Feature Specification: v0.8 — Runtime Bridge and Positioning

**Feature Branch**: `011-runtime-bridge-v0-8`
**Created**: 2026-04-08
**Status**: Draft
**Input**: User description: "specify the implementation plan for issues #253–#257"

## Overview

Ziran's wedge is pre-deploy, graph-based discovery of dangerous agent tool-chains. Users increasingly ask for a "runtime story" and confuse Ziran with runtime guardrails (NeMo, Lakera, Invariant, Microsoft AGT). This release bridges Ziran to the runtime ecosystem **without** putting Ziran on the request path, and positions Ziran clearly in the agent-security landscape.

This is an umbrella release spec that bundles five GitHub issues delivering a coherent "runtime bridge + positioning" theme:

- **#253** Export findings as runtime guardrail policies (OPA/Rego, Cedar, NeMo, Invariant)
- **#254** Post-hoc trace analyzer (ingest OTel/Langfuse, replay through knowledge graph)
- **#255** Continuous MCP registry scanning (rug-pull, typosquatting, drift) — MCP-only in v0.8; A2A deferred
- **#256** Native CI integrations beyond GitHub Actions (GitLab, Jenkins, CircleCI, Azure)
- **#257** Docs: position Ziran in the agent-security landscape (pre-deploy vs runtime)

## Clarifications

### Session 2026-04-09

- Q: Do all five issues ship together as v0.8, or does v0.8 ship only the P1 pair? → A: All five (#253–#257) ship together in v0.8.
- Q: Does the registry watcher (#255) cover both MCP and A2A in v0.8? → A: MCP-only in v0.8; A2A support deferred to a follow-up issue.
- Q: Are both OTel and Langfuse trace adapters required for v0.8? → A: Yes, both OTel JSONL and Langfuse (file export + API pull) are required in v0.8.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Export Ziran findings as runtime guardrail policies (Priority: P1)

A platform security engineer runs a Ziran scan against their agent stack and gets a list of dangerous tool-chain findings (e.g. `read_file → http_request` data exfiltration). They already operate a runtime guardrail (NeMo, Invariant, OPA-backed gateway, or AWS Cedar). Instead of hand-translating each finding into guardrail syntax, they run one command to produce a ready-to-apply policy bundle and check it into their guardrail repo.

**Why this priority**: Without policy export, Ziran findings stop at a report. With export, Ziran becomes the upstream of every runtime guardrail in the ecosystem — maximum leverage for minimum surface area, and directly addresses the "what do I do with these findings?" question every adopter asks.

**Independent Test**: Given a sample campaign result containing a canonical `read_file → http_request` finding, running the export command with each supported format produces a syntactically valid policy file that denies that exact tool-call sequence and includes a comment linking back to the Ziran finding ID. Each format can be validated by its native tooling (policy linter / parser) without Ziran being present.

**Acceptance Scenarios**:

1. **Given** a campaign result file containing at least one high-severity finding, **When** the user exports to a Rego format, **Then** the output is a valid Rego module that denies the exact observed tool-call sequence and references the finding ID in a comment.
2. **Given** the same campaign result, **When** the user exports to any of the other supported guardrail formats, **Then** a format-appropriate policy file is produced with the same denial semantics and traceability back to the finding ID.
3. **Given** a campaign result with findings below the configured severity floor, **When** the user runs export, **Then** no policy is emitted for those findings and the user is told how many were skipped.

---

### User Story 2 — Analyze production agent traces against the knowledge graph (Priority: P1)

An SRE exports recent production agent traces from their observability stack (OTel JSONL or Langfuse). They run a single command pointing Ziran at the trace file or backend. Ziran reconstructs tool-call sequences per session, walks its dangerous-chain patterns against the observed sequences, and produces the standard report with findings annotated by first/last seen timestamp and occurrence count. Findings that were only hypothetical in the pre-deploy scan now carry a badge showing they actually executed in production.

**Why this priority**: This is Ziran's on-brand runtime story: same graph, same patterns, zero request-path involvement, no SLA burden. It also pairs directly with Story 1 — observed chains become exported guardrail rules — closing the loop from pre-deploy to production evidence to enforcement.

**Independent Test**: Given a synthetic OTel trace fixture encoding a known dangerous pattern, running the analyze command produces the standard report with that finding flagged, annotated with occurrence count and timestamps, and marked as "observed in production". The command works end-to-end without needing a live scan.

**Acceptance Scenarios**:

1. **Given** an OTel JSONL trace file containing a known dangerous tool-call sequence, **When** the user runs the trace analyzer, **Then** the output report flags the matching finding with occurrence count, first seen timestamp, and last seen timestamp.
2. **Given** a Langfuse export or live backend containing traces without dangerous patterns, **When** the user runs the analyzer, **Then** the report contains zero findings and exits cleanly.
3. **Given** traces spanning multiple sessions and agents, **When** the analyzer runs, **Then** tool-call sequences are reconstructed per session/agent so patterns are not falsely matched across unrelated sessions.

---

### User Story 3 — Continuously watch MCP registries for drift and typosquats (Priority: P2)

A developer depends on several third-party MCP servers. They declare these dependencies in a config file and schedule Ziran's registry watcher (manually, cron, or in CI). On each run the watcher re-fetches each server's manifest, compares it to the last known snapshot, and flags: added/removed tools, modified tool descriptions (possible injected prompts), parameter schema changes, permission escalations, and names that look like typosquats of a configured allowlist. Findings flow through the standard report formats; an included CI example opens an issue on drift. (A2A agent watching is deferred to a follow-up issue.)

**Why this priority**: Supply-chain drift in the MCP ecosystem is a real and rising risk (rug-pulls, hidden instructions in updated descriptions). This extends Ziran's pre-deploy mission into continuous coverage of an area no OSS tool covers well. Medium priority because it's additive and the scan-time MCP coverage already exists.

**Independent Test**: Given two fixture manifests for the same MCP server where the second adds a tool and modifies a description, the watcher detects both changes, emits findings with appropriate severity, and writes an updated snapshot. Typosquatting detection is tested independently with a name list and a crafted near-duplicate.

**Acceptance Scenarios**:

1. **Given** a registry config listing one MCP server and a stored snapshot, **When** the upstream manifest gains a new tool, **Then** the watcher emits a "new tool added" finding and updates the snapshot.
2. **Given** a stored snapshot of an MCP server, **When** a tool's description has been modified, **Then** the watcher emits a "description drift" finding with before/after context.
3. **Given** a registry config that includes a name similar to a protected allowlist entry, **When** the watcher runs, **Then** a typosquatting finding is emitted with the suspected canonical name.

---

### User Story 4 — Use Ziran as a quality gate in non-GitHub CI systems (Priority: P2)

A team on GitLab (or Jenkins, CircleCI, Azure Pipelines) wants to adopt Ziran as a CI quality gate but currently only finds first-class docs for GitHub Actions. They copy a ready-to-use pipeline template for their CI system, point it at their project, and get the same `essential | standard | comprehensive` coverage knob and gate behavior already available on GitHub, with findings uploaded to their platform's native security dashboard where supported.

**Why this priority**: Small per-platform effort with disproportionate adoption reach. Medium priority because it's distribution/marketing rather than new capability.

**Independent Test**: Each CI template file is lintable by its platform's native parser or schema, and a smoke test in Ziran's CI validates each template syntactically. A human can follow the docs page and successfully run Ziran in a minimal fixture project on at least one non-GitHub CI platform.

**Acceptance Scenarios**:

1. **Given** the documented CI template for GitLab (or Jenkins / CircleCI / Azure), **When** a developer follows the docs and commits the template, **Then** the pipeline runs Ziran and produces a gated pass/fail plus the standard findings output on that platform.
2. **Given** a supported CI platform with a native security dashboard, **When** the template runs successfully, **Then** findings are uploaded to that dashboard in SARIF form.
3. **Given** any supported template file, **When** Ziran's own CI runs its lint-only smoke test, **Then** syntactic validity is verified so the templates do not rot.

---

### User Story 5 — Understand where Ziran fits in the agent-security landscape (Priority: P3)

A user evaluating agent-security tools lands on Ziran's README or docs. Within one page view they can see a layered diagram placing Ziran in the pre-deploy layer alongside Promptfoo and Garak, runtime governance tools (NeMo, Lakera, Invariant, AGT) in the runtime enforcement layer, and observability tools (Langfuse, LangSmith, Phoenix) in the observability layer. The page explains that Ziran complements rather than competes with runtime governance and links to the policy-export and trace-analyzer features as the official integration paths.

**Why this priority**: Docs/positioning — no new product capability, but materially reduces "Ziran vs AGT?" confusion that will spike with AGT's public preview. Deferred to P3 because Stories 1 and 2 are the substance the docs page will reference.

**Independent Test**: A reader unfamiliar with Ziran can, after one minute on the landscape page, correctly name Ziran's layer and identify at least two categories of tools it is designed to work alongside.

**Acceptance Scenarios**:

1. **Given** a reader on the README, **When** they scroll to the "Works With" section, **Then** they see runtime governance tools listed explicitly as complements.
2. **Given** a reader on the docs site, **When** they open the landscape page, **Then** they see a three-layer diagram and an explanation of which OWASP list each layer covers.
3. **Given** the landscape page exists, **When** the policy-export and trace-analyzer features ship, **Then** the landscape page cross-links to them as the official integration paths.

---

### Edge Cases

- Campaign result / trace files that are empty, malformed, or reference finding IDs that no longer exist in the current pattern library.
- Trace sessions that interleave tool calls from multiple agents — sessions must be separated before pattern matching.
- Registry watcher running against a manifest that is temporarily unreachable (network error) — must not corrupt the snapshot or emit a false "tool removed" finding.
- Policy export for findings whose tool-call sequence cannot be cleanly expressed in a given target format — must emit a clear skip reason rather than producing an incorrect policy.
- CI templates running against projects with no findings — must exit cleanly with gate passing.
- Typosquatting check producing false positives on legitimate forks or regional variants — allowlist must support explicit exemptions.

## Requirements *(mandatory)*

### Functional Requirements

**Policy Export (#253)**

- **FR-001**: System MUST accept a campaign result file as input and emit a runtime guardrail policy bundle to a user-specified output directory.
- **FR-002**: System MUST support at least four target formats: Rego (OPA), Cedar, NeMo Guardrails Colang, and Invariant Labs policy DSL.
- **FR-003**: System MUST only emit policies for findings at or above a configurable severity floor and MUST report how many findings were skipped.
- **FR-004**: Every generated policy file MUST include a header comment linking back to the originating Ziran finding ID.
- **FR-005**: System MUST expose policy export through both the CLI and the Python API.

**Trace Analyzer (#254)**

- **FR-006**: System MUST ingest OpenTelemetry JSONL trace files and Langfuse traces (file export and backend pull).
- **FR-007**: System MUST reconstruct tool-call sequences grouped by session and agent before pattern matching.
- **FR-008**: System MUST walk the existing dangerous-chain pattern library against observed sequences and emit findings in the standard report formats.
- **FR-009**: Findings produced by trace analysis MUST include an "observed in production" marker, first seen timestamp, last seen timestamp, and occurrence count.
- **FR-010**: System MUST expose trace analysis through both the CLI and the Python API.

**Registry Watcher (#255)**

- **FR-011**: System MUST read a user-supplied registry configuration listing MCP servers to watch. (A2A agent support deferred to a follow-up issue.)
- **FR-012**: System MUST persist a snapshot of each watched manifest and detect diffs on subsequent runs covering added/removed tools, description changes, parameter schema changes, and permission changes.
- **FR-013**: System MUST perform typosquatting detection against a configurable allowlist and flag suspicious names.
- **FR-014**: System MUST emit drift and typosquat findings through the standard report formats.
- **FR-015**: System MUST ship a reference example showing how to run the watcher in CI and open a tracking issue on drift.

**CI Integrations (#256)**

- **FR-016**: System MUST ship ready-to-use pipeline templates for GitLab CI, Jenkins, CircleCI, and Azure Pipelines under the examples directory.
- **FR-017**: Each CI template MUST mirror the existing GitHub Action's `essential | standard | comprehensive` coverage knob and gate-on-severity behavior.
- **FR-018**: Each CI template MUST upload SARIF findings to the platform's native security dashboard where such a dashboard exists.
- **FR-019**: Ziran's own CI pipeline MUST lint every shipped CI template on each run to prevent bitrot.

**Landscape Docs (#257)**

- **FR-020**: README "Works With" section MUST list runtime governance tools (NeMo, Lakera, Invariant, Microsoft AGT) explicitly as complements.
- **FR-021**: Docs site MUST include a landscape page with a three-layer diagram (pre-deploy testing, runtime enforcement, observability) placing Ziran and named peer tools in the correct layer.
- **FR-022**: Landscape page MUST note that Ziran covers OWASP LLM Top 10 pre-deploy and that runtime governance tools cover OWASP Agentic Top 10 at runtime.
- **FR-023**: Landscape page MUST cross-link to the policy export (#253) and trace analyzer (#254) features as the official integration paths.

**Cross-cutting**

- **FR-024**: All new commands MUST be documented under the project's existing docs site with at least one worked example per command.
- **FR-025**: All new commands MUST include automated tests covering their primary happy path and at least one failure/skip path.

### Key Entities

- **Campaign Result**: Existing Ziran output describing findings from a scan; used as input for policy export.
- **Finding**: Existing concept; gains new optional fields for "observed in production" state (trace source, first/last seen, occurrence count).
- **Trace**: A time-ordered sequence of tool calls from production, grouped by session and agent, ingested from OTel or Langfuse.
- **Manifest Snapshot**: A stored copy of an MCP server manifest used to diff against future fetches.
- **Registry Config**: User-maintained declaration of watched MCP servers and the typosquatting allowlist.
- **Guardrail Policy**: Output artifact for each supported target format (Rego, Cedar, Colang, Invariant DSL) derived from a finding.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user with a campaign result file can produce a runtime guardrail policy bundle for any supported format in under one minute and without hand-editing the output.
- **SC-002**: A user with a production trace file can obtain a findings report annotated with production evidence in under five minutes, with no pre-deploy scan required.
- **SC-003**: At least 90% of findings that match a dangerous-chain pattern in a production trace fixture are also flagged by the equivalent pre-deploy scan (parity between runtime and pre-deploy analysis).
- **SC-004**: The registry watcher detects 100% of injected drift events (added tool, modified description, typosquatted name) in the test fixture suite on the first run after the change.
- **SC-005**: All four new CI templates can be adopted by following the docs alone (no source-code diving), verified by a dry-run on a fixture project for each platform.
- **SC-006**: After the landscape docs ship, the rate of "Ziran vs runtime tool X" confusion — measured via GitHub issues and discussions tagged as clarification requests — trends down over the following release cycle.
- **SC-007**: Zero regressions in existing scan-path performance and no new runtime dependencies on the scan hot path after this release.

## Assumptions

- The existing campaign result JSON schema is stable enough to be the canonical input for policy export; no breaking change is required.
- The existing dangerous-chain pattern engine can be invoked against arbitrary tool-call sequences (not only sequences produced by a live scan). If it cannot, a thin adapter is acceptable as long as it reuses the same pattern definitions.
- OpenTelemetry JSONL and Langfuse are sufficient trace sources for the initial release; additional sources (LangSmith, Phoenix, custom) can be added in later iterations without reshaping the analyzer.
- The project already ships SARIF output suitable for upload to GitLab and Azure security dashboards; no new output format is required for CI integrations.
- Snapshot storage for the registry watcher can be local to the user's workspace (no centralized service) for the first release.
- Policy export is best-effort per format: if a finding's tool-call sequence cannot be represented cleanly in a target format, skipping with a clear reason is acceptable in v0.8.
- All five issues ship together as the v0.8 release; they are sequenced P1 → P3 but share a single release cycle.

## Dependencies

- Existing pattern engine and knowledge graph (no changes expected, but the trace analyzer will exercise it on externally supplied sequences).
- Existing campaign result / report renderer pipeline (must accept new optional "observed in production" metadata on findings).
- Existing SARIF output path (reused by new CI templates).
- Existing MCP adapter (reused by the registry watcher; A2A adapter not needed in v0.8).

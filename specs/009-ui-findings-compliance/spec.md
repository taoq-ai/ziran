# Feature Specification: UI Batch 2 — Findings Management, Compliance & Design System

**Feature Branch**: `009-ui-findings-compliance`
**Created**: 2026-03-24
**Status**: Draft
**Input**: GitHub issues #172, #176, #179, #180, #98
**Scope**: Community (open-source) tier only — no auth, no enterprise features

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Findings Management Page (Priority: P1)

After a scan completes, a security analyst navigates to the Findings page to triage vulnerability results. They see a sortable, filterable table of all findings across all runs. They filter by severity (Critical/High), search for "prompt injection", review the full attack transcript for a specific finding, and mark false positives. They then bulk-select resolved findings and mark them as "Fixed".

**Why this priority**: Findings triage is the core value proposition — without it, users must parse raw JSON output or CLI reports. This is the single most impactful feature for day-to-day security workflows.

**Independent Test**: Run a scan via the UI, navigate to Findings page, verify findings appear with correct severity/category, filter by severity, open a finding detail, change its status, reload and confirm status persisted.

**Acceptance Scenarios**:

1. **Given** a completed scan with findings, **When** user navigates to /findings, **Then** all findings display in a paginated table with columns: severity, title, category, target, status, detected date
2. **Given** the findings table, **When** user applies severity filter "Critical", **Then** only critical findings are shown and the count updates
3. **Given** a finding in "Open" status, **When** user changes status to "False Positive", **Then** status persists across page reload
4. **Given** multiple findings selected, **When** user clicks "Mark as Fixed", **Then** all selected findings update to "Fixed" status
5. **Given** a finding row, **When** user clicks to open detail, **Then** full attack/response transcript, detection metadata, and remediation guidance are displayed

---

### User Story 2 — TaoQ Design System (Priority: P1)

A user launches the ZIRAN web UI and sees a polished, branded interface with TaoQ's dark-first design language — teal accent colors, DM Sans typography, consistent severity color coding across all pages and components.

**Why this priority**: Visual consistency and branding are critical for trust in a security tool. The design system also establishes patterns used by all subsequent UI features.

**Independent Test**: Open the UI in a browser, verify TaoQ branding (teal accents, dark background, DM Sans font, logo in sidebar), toggle light mode, verify all existing pages (Dashboard, NewRun, RunDetail) render with the updated design tokens.

**Acceptance Scenarios**:

1. **Given** the UI loads, **When** user views any page, **Then** TaoQ color palette (teal accent, dark backgrounds, semantic severity colors) is applied consistently
2. **Given** the sidebar, **When** user views the header area, **Then** TaoQ logo and brand name are visible
3. **Given** dark mode is default, **When** user toggles to light mode, **Then** all components switch to light theme correctly
4. **Given** any severity badge, **When** rendered, **Then** it uses semantic colors: Critical=red, High=orange, Medium=yellow, Low=teal, Info=gray

---

### User Story 3 — OWASP LLM Top 10 Compliance Matrix (Priority: P2)

After reviewing scan results, a compliance officer navigates to a compliance view showing the OWASP LLM Top 10 coverage matrix. Each of the 10 categories displays a status (tested/not tested), finding count, and severity-based color coding. Clicking a category filters the findings table to that category.

**Why this priority**: Compliance mapping is a key differentiator and required for enterprise adoption, but it depends on findings data being available first.

**Independent Test**: Run a scan that covers at least 3 OWASP categories, navigate to the compliance view, verify correct category mapping, click a category cell, verify findings table filters to that category.

**Acceptance Scenarios**:

1. **Given** scan results with OWASP-mapped findings, **When** user views the compliance matrix, **Then** all 10 LLM categories are displayed with correct finding counts
2. **Given** a category with critical findings, **When** rendered, **Then** the cell shows red status color
3. **Given** a category with no matching attack vectors in any scan, **When** rendered, **Then** the cell shows gray "Not Tested" status
4. **Given** a category cell, **When** user clicks it, **Then** the findings table filters to show only findings in that OWASP category
5. **Given** a category cell, **When** user hovers, **Then** a tooltip shows the full category description

---

### User Story 4 — Findings Database Schema & API (Priority: P1)

The system denormalizes findings from scan result JSON into queryable database rows after each scan completes. Findings are deduplicated across scans using a fingerprint hash. The REST API exposes endpoints for listing, filtering, detail retrieval, status updates, bulk actions, and aggregate statistics.

**Why this priority**: This is the data layer that powers User Stories 1 and 3. Without it, findings cannot be queried, filtered, or tracked.

**Independent Test**: Run two scans against the same target, verify findings are extracted and deduplicated in the database, call the findings API with various filter combinations, verify correct results and pagination.

**Acceptance Scenarios**:

1. **Given** a scan completes, **When** results are persisted, **Then** individual findings are extracted from result JSON into the findings table
2. **Given** two scans produce the same vulnerability, **When** findings are extracted, **Then** the duplicate is detected by fingerprint and linked rather than duplicated
3. **Given** findings exist, **When** API is called with severity=critical&status=open, **Then** only matching findings are returned with correct pagination metadata
4. **Given** a finding ID, **When** detail API is called, **Then** full attack transcript, detection metadata, and remediation guidance are returned
5. **Given** a list of finding IDs, **When** bulk status update is called, **Then** all specified findings update atomically

---

### User Story 5 — Community Export Endpoints (Priority: P3)

A user wants to export findings or run results for external consumption. They can download filtered findings as CSV or JSON, or export a run configuration as YAML or a summary as Markdown.

**Why this priority**: Export is a convenience feature that adds value but is not required for core workflows.

**Independent Test**: With findings data present, call the CSV export endpoint with a severity filter, verify the downloaded file contains only matching findings with correct headers.

**Acceptance Scenarios**:

1. **Given** findings exist, **When** user requests CSV export with filters, **Then** a CSV file downloads containing only matching findings
2. **Given** findings exist, **When** user requests JSON export, **Then** a JSON file downloads with the same structure as the API response
3. **Given** a run ID, **When** user requests YAML export, **Then** the scan configuration is exported as a valid YAML file
4. **Given** a run ID, **When** user requests Markdown export, **Then** a formatted report is generated with summary, findings table, and compliance coverage

---

### Edge Cases

- What happens when a scan produces zero findings? The findings table shows an empty state with a message and link to start a new scan.
- What happens when the findings table has thousands of results? Pagination limits to configurable page sizes (default 25, max 100).
- What happens when a finding's status is changed while another user bulk-updates it? Last-write-wins semantics (no auth/locking in community tier).
- What happens when a scan is cancelled mid-extraction? Partial findings are still persisted; extraction can be re-triggered.
- What happens when the OWASP matrix renders for a scan with no OWASP-mapped attacks? All 10 cells show "Not Tested" in gray.
- What happens when export is requested with no matching findings? An empty file is returned with headers only (CSV) or empty array (JSON).

## Requirements *(mandatory)*

### Functional Requirements

**Findings Data Layer**
- **FR-001**: System MUST extract individual findings from scan result JSON into a queryable findings table after each scan completes
- **FR-002**: System MUST deduplicate findings across scans using a fingerprint hash derived from target, attack name, category, and response pattern
- **FR-003**: System MUST store finding severity levels: critical, high, medium, low, info
- **FR-004**: System MUST track finding status: open, fixed, false_positive, ignored
- **FR-005**: System MUST store compliance mappings linking findings to framework controls (OWASP LLM Top 10)

**Findings API**
- **FR-006**: System MUST provide a paginated findings list endpoint supporting filters: run_id, severity, status, category, target, text search
- **FR-007**: System MUST provide a finding detail endpoint returning full attack transcript, detection metadata, and remediation guidance
- **FR-008**: System MUST provide a finding status update endpoint accepting the four status values
- **FR-009**: System MUST provide a bulk status update endpoint accepting a list of finding IDs and a target status
- **FR-010**: System MUST provide a findings statistics endpoint returning counts grouped by severity, category, and status

**Findings UI**
- **FR-011**: Users MUST be able to view findings in a sortable table with columns: severity, title, category, target, status, detected date
- **FR-012**: Users MUST be able to filter findings by severity, status, category, target, and free-text search
- **FR-013**: Users MUST be able to change a finding's status via the table or detail view
- **FR-014**: Users MUST be able to select multiple findings and apply bulk status changes
- **FR-015**: Users MUST be able to view a finding's full detail including attack/response transcript

**OWASP Compliance**
- **FR-016**: System MUST display an OWASP LLM Top 10 matrix with all 10 categories
- **FR-017**: Each matrix cell MUST show finding count and severity-based color coding
- **FR-018**: Clicking a matrix cell MUST filter the findings view to that OWASP category
- **FR-019**: System MUST provide a compliance API endpoint returning OWASP coverage data

**Design System**
- **FR-020**: System MUST apply TaoQ design tokens: teal accent (#4fd1c5), dark background (#0a0a0a), DM Sans font
- **FR-021**: System MUST render dark mode as default with light mode toggle
- **FR-022**: System MUST use semantic severity colors consistently: Critical=red, High=orange, Medium=yellow, Low=teal, Info=gray
- **FR-023**: System MUST display TaoQ logo in the sidebar header

**Export**
- **FR-024**: System MUST export findings as CSV with current filter parameters applied
- **FR-025**: System MUST export findings as JSON
- **FR-026**: System MUST export run configuration as YAML
- **FR-027**: System MUST export run summary as Markdown report

### Key Entities

- **Finding**: A single vulnerability discovered during a scan. Has severity, category, status, and links to its parent run. Contains the full attack/response transcript and remediation guidance. Deduplicated across scans by fingerprint.
- **Compliance Mapping**: Links a finding to a compliance framework control (e.g., OWASP LLM01). One finding may map to multiple controls.
- **Export Job**: Represents a file export request with format, filters, and completion status (included in schema for future async support).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can find and triage a specific vulnerability from scan results within 30 seconds using the findings table filters
- **SC-002**: All OWASP LLM Top 10 categories display correct coverage status within 2 seconds of page load
- **SC-003**: Findings page loads and renders the first page of results within 1 second for up to 10,000 findings
- **SC-004**: Bulk status updates process up to 100 findings in under 2 seconds
- **SC-005**: Exported CSV/JSON files include all findings matching the applied filters
- **SC-006**: All UI components render with consistent TaoQ branding across all pages
- **SC-007**: Dark-to-light mode toggle applies within 100ms with no layout shift

## Assumptions

- No authentication in this batch — community tier is single-user. Auth (issue #171) will be a separate batch.
- Compliance mappings are limited to OWASP LLM Top 10 in this batch. NIST, EU AI Act, and MITRE ATLAS are enterprise features for future batches.
- Finding deduplication uses a simple hash-based fingerprint. ML-based dedup is out of scope.
- Export operations are synchronous for community tier (no background job queue). The export_jobs table is included in the schema for future async support.
- The OWASP compliance matrix is displayed on the Run Detail page as a component, and also available as a standalone page.
- Enterprise models (workspaces, workspace_members, finding_comments, audit_log, shared_links) are out of scope for this batch.
- The findings extraction happens as a post-processing step in the RunManager after scan completion.

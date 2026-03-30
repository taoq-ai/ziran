# Feature Specification: UI Batch 3 — Pages, Polish & Docker

**Feature Branch**: `010-ui-polish-pages`
**Created**: 2026-03-30
**Status**: Draft
**Input**: GitHub issues #99, #100, #101, #102, #104, #174
**Scope**: Community (single-developer) edition only

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Knowledge Graph Visualization (Priority: P1)

After a scan completes, a security researcher opens the Run Detail page and sees an interactive knowledge graph rendered from the scan's graph state. They click nodes to inspect capabilities, tools, and vulnerabilities. They click a critical path from the vulnerability list to highlight it in the graph, dimming unrelated nodes. They use the toolbar to fit the view, toggle physics, and search for specific nodes.

**Why this priority**: The knowledge graph is ZIRAN's core differentiator — it visually reveals how vulnerabilities chain together through agent capabilities and tool access. This is the most requested feature from CLI users.

**Independent Test**: Run a scan that produces a non-empty graph, open Run Detail, verify graph renders with correct node colors/shapes per type, click a node to see its detail overlay, click a critical path to see it highlighted.

**Acceptance Scenarios**:

1. **Given** a completed scan with graph data, **When** user opens Run Detail, **Then** the knowledge graph renders with correct node types (capability=blue circle, tool=green diamond, vulnerability=red triangle, etc.)
2. **Given** the rendered graph, **When** user clicks a node, **Then** a detail overlay shows the node's ID, type, risk level, severity, and connections
3. **Given** the vulnerability list, **When** user clicks a critical path, **Then** the graph highlights that path with red edges and dims other nodes
4. **Given** the graph toolbar, **When** user clicks "Fit View", **Then** the graph zooms to show all nodes
5. **Given** a run with no graph data, **When** user opens Run Detail, **Then** a graceful empty state is shown instead of the graph

---

### User Story 2 — Attack Library Browser (Priority: P1)

A developer navigates to the Attack Library page to browse all available attack vectors bundled with ZIRAN. They search for "prompt injection", filter by severity "critical", and expand a vector to see its prompt templates, OWASP mappings, and success criteria. They use this to understand what attacks ZIRAN supports before configuring a scan.

**Why this priority**: Understanding the attack library is essential for configuring effective scans. Without this, users must read YAML files directly.

**Independent Test**: Open the Library page, verify all bundled attack vectors appear, filter by category, expand a vector to see its prompts.

**Acceptance Scenarios**:

1. **Given** the Library page, **When** it loads, **Then** all bundled attack vectors are displayed in a searchable table with stats summary
2. **Given** the vector table, **When** user filters by category "prompt_injection" and severity "critical", **Then** only matching vectors appear
3. **Given** a vector row, **When** user expands it, **Then** prompt templates, OWASP mappings, description, and success criteria are shown
4. **Given** the search field, **When** user types "exfiltration", **Then** the table filters to vectors matching that text in name, description, or tags

---

### User Story 3 — Config Presets & Settings (Priority: P2)

A developer opens the Settings page to configure default scan parameters (coverage level, strategy, concurrency). They save a preset named "Quick Smoke Test" with low coverage and fast settings. Later, on the New Run page, they select this preset from a dropdown and all form fields populate automatically.

**Why this priority**: Presets save time for repeated scan configurations, but scans work fine without them via manual form entry.

**Independent Test**: Open Settings, create a preset, go to New Run, select the preset, verify form fields populate.

**Acceptance Scenarios**:

1. **Given** the Settings page, **When** user creates a preset with name, description, and config, **Then** it appears in the presets list
2. **Given** an existing preset, **When** user edits it, **Then** changes persist after page reload
3. **Given** the New Run page, **When** user selects a preset from the dropdown, **Then** all form fields populate with the preset's values
4. **Given** the New Run page with filled fields, **When** user clicks "Save as Preset", **Then** current form state is saved as a new preset

---

### User Story 4 — UX Polish (Priority: P2)

A developer uses the UI and encounters loading states (skeleton loaders on tables), meaningful empty states (no runs yet → CTA to start first scan), proper error handling (API failures with retry buttons), and a responsive layout that works on tablet screens.

**Why this priority**: Polish makes the difference between a prototype and a usable tool. However, the UI is functional without it.

**Independent Test**: Open the Dashboard with no data (empty state), trigger an API error (error boundary), resize browser to tablet width (responsive), navigate to a non-existent run ID (404 page).

**Acceptance Scenarios**:

1. **Given** a page is loading data, **When** the API call is in flight, **Then** skeleton loaders appear instead of blank content
2. **Given** the Dashboard with no runs, **When** page loads, **Then** an empty state with "Start your first scan" CTA is shown
3. **Given** an API error occurs, **When** user sees the error, **Then** a user-friendly message with a retry button is displayed
4. **Given** a browser at 768px width, **When** user views the UI, **Then** the sidebar collapses to a hamburger menu and tables scroll horizontally
5. **Given** a non-existent run ID in the URL, **When** page loads, **Then** a 404 page with navigation back to Dashboard is shown

---

### User Story 5 — Docker Support (Priority: P3)

A developer clones the repo and runs `docker compose up` to get a working ZIRAN UI with PostgreSQL without installing Python, Node.js, or PostgreSQL locally. The container serves the bundled frontend and auto-applies database migrations.

**Why this priority**: Docker simplifies local setup but isn't required — developers can install directly via pip.

**Independent Test**: Run `docker compose up`, wait for startup, open `http://localhost:8484`, verify the UI loads and health endpoint returns `database: connected`.

**Acceptance Scenarios**:

1. **Given** the repo is cloned, **When** user runs `docker compose up`, **Then** the UI starts with PostgreSQL and is accessible at port 8484
2. **Given** the Docker container, **When** it starts, **Then** database migrations auto-apply
3. **Given** environment variables in `.env`, **When** container starts, **Then** they are available to the ZIRAN process
4. **Given** a persistent volume, **When** container restarts, **Then** scan data and findings are preserved

---

### User Story 6 — Enhanced Community Exports (Priority: P3)

Export endpoints from batch 2 are already functional (CSV, JSON, YAML, Markdown). This story adds UI export buttons to the Findings page, Run Detail page, and Dashboard so users can trigger exports directly from the interface without using curl.

**Why this priority**: Export APIs exist; this just adds UI buttons to invoke them. Low effort, quality-of-life improvement.

**Independent Test**: Open the Findings page with data, click "Export CSV" button, verify a CSV file downloads with the currently-applied filters.

**Acceptance Scenarios**:

1. **Given** the Findings page with filters applied, **When** user clicks "Export CSV", **Then** a CSV file downloads containing only the filtered findings
2. **Given** the Run Detail page, **When** user clicks "Export Report", **Then** a dropdown shows Markdown and YAML options
3. **Given** the export dropdown, **When** user selects "Markdown", **Then** a .md file downloads with the run summary report

---

### Edge Cases

- What happens when the knowledge graph has 500+ nodes? Physics should be disabled by default for large graphs (>200 nodes) and the graph stabilized before display.
- What happens when the attack library YAML files are missing or corrupted? Show an error message with the specific file that failed to load.
- What happens when a preset name already exists? Return a validation error and prevent overwriting.
- What happens when Docker starts without a `.env` file? Start with defaults; show a warning in logs that no LLM API key is configured.
- What happens when the browser is narrower than 768px (phone)? Show a banner suggesting desktop use; layout is best-effort but not guaranteed.

## Requirements *(mandatory)*

### Functional Requirements

**Knowledge Graph**
- **FR-001**: System MUST render an interactive graph from scan graph_state_json data
- **FR-002**: System MUST display distinct visual styles per node type (capability, tool, vulnerability, data_source, phase, agent_state)
- **FR-003**: Users MUST be able to click a node to see its detail overlay
- **FR-004**: Users MUST be able to highlight a critical path from the vulnerability list
- **FR-005**: System MUST provide a toolbar with fit view, physics toggle, and search

**Attack Library**
- **FR-006**: System MUST provide an API endpoint listing all bundled attack vectors with filtering
- **FR-007**: System MUST display attack vectors in a searchable, filterable table
- **FR-008**: Users MUST be able to expand a vector to see prompt templates and OWASP mappings
- **FR-009**: System MUST show aggregate stats (total vectors, by category, by severity)

**Config Presets**
- **FR-010**: System MUST provide CRUD API endpoints for config presets
- **FR-011**: Users MUST be able to create, edit, and delete presets from the Settings page
- **FR-012**: Users MUST be able to select a preset on the New Run page to populate form fields
- **FR-013**: Users MUST be able to save current New Run form state as a new preset

**UX Polish**
- **FR-014**: System MUST show skeleton loaders during data fetching
- **FR-015**: System MUST show meaningful empty states with calls-to-action
- **FR-016**: System MUST show error boundaries with retry buttons on API failures
- **FR-017**: System MUST provide a 404 page for invalid routes
- **FR-018**: System MUST collapse sidebar to hamburger menu at tablet breakpoints

**Docker**
- **FR-019**: System MUST provide a multi-stage Dockerfile building frontend and Python runtime
- **FR-020**: System MUST provide a docker-compose.yml with PostgreSQL service
- **FR-021**: System MUST provide a `.env.example` file documenting required environment variables

**Export UI**
- **FR-022**: System MUST provide export buttons on the Findings page and Run Detail page
- **FR-023**: Export MUST respect currently-applied filters

### Key Entities

- **Config Preset**: Saved scan configuration with name, description, and full config object. Uses the existing `config_presets` table from batch 1.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Knowledge graph renders within 2 seconds for graphs with up to 200 nodes
- **SC-002**: Attack Library page loads all vectors within 1 second
- **SC-003**: Config preset selection populates form fields within 200ms
- **SC-004**: All pages display skeleton loaders within 100ms of navigation
- **SC-005**: Docker compose starts a working environment within 60 seconds on first build
- **SC-006**: UI remains usable at 768px viewport width

## Assumptions

- No authentication — single-developer use, all endpoints public.
- vis-network is already in the npm dependencies from the foundation spec.
- The `config_presets` SQLAlchemy model already exists (created in batch 1).
- The export API endpoints already exist (created in batch 2) — this story only adds UI buttons.
- SARIF and PDF exports are deferred to enterprise/SaaS tier.
- The Docker setup uses PostgreSQL (not SQLite) to match the production setup.
- Phone-width (<768px) layout is best-effort, not a requirement.

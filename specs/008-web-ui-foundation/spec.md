# Feature Specification: Web UI Foundation

**Feature Branch**: `008-web-ui-foundation`
**Created**: 2026-03-23
**Status**: Draft
**Input**: User description: "Add web UI foundation to ziran - FastAPI backend with PostgreSQL (asyncpg + Alembic), React frontend (Vite + TypeScript + shadcn/ui + Tailwind) bundled into PyPI wheel, `ziran ui` CLI command. Frontend source at ui/ repo root, builds to ziran/interfaces/web/static/. Covers GitHub issues #105, #86, #88, #92, #103."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Launch Web Dashboard (Priority: P1)

A security engineer installs ziran with the UI optional dependency and launches the web dashboard from the command line. The dashboard opens in their browser showing an empty state with navigation, ready for future scan management features.

**Why this priority**: This is the foundational experience — without a running server and visible frontend, no other UI features can exist. It validates the entire stack end-to-end (CLI command, server, database connection, SPA serving).

**Independent Test**: Can be fully tested by running `pip install ziran[ui]` followed by `ziran ui`, then opening the browser to verify the dashboard loads. Delivers the core infrastructure that all subsequent UI features build upon.

**Acceptance Scenarios**:

1. **Given** ziran is installed with the UI extra, **When** the user runs the dashboard command, **Then** a web server starts on the default address and the terminal displays the URL
2. **Given** the web server is running, **When** the user opens the displayed URL in a browser, **Then** they see a dashboard page with sidebar navigation and an empty state message
3. **Given** ziran is installed without the UI extra, **When** the user runs the dashboard command, **Then** a helpful error message explains how to install the UI dependencies
4. **Given** the web server is running, **When** the user navigates to the health check endpoint, **Then** they receive a successful response

---

### User Story 2 - Developer Frontend Workflow (Priority: P2)

A contributor working on the web UI starts the frontend development server with hot module replacement. Changes to frontend components are reflected instantly in the browser without restarting the backend.

**Why this priority**: Enables productive frontend development. Without this, every UI change requires a full rebuild — making iterative development impractical.

**Independent Test**: Can be tested by running the frontend dev server alongside the backend in dev mode, editing a component file, and verifying the change appears in the browser within seconds.

**Acceptance Scenarios**:

1. **Given** the developer has a frontend runtime installed, **When** they start the frontend dev server, **Then** it launches with hot module replacement enabled
2. **Given** both dev servers are running, **When** the developer edits a frontend component, **Then** the browser updates automatically without a full page reload
3. **Given** the frontend dev server is running, **When** it makes API calls, **Then** requests to API endpoints are proxied to the backend server transparently

---

### User Story 3 - PyPI Distribution with Bundled Frontend (Priority: P2)

A release manager builds the ziran package for distribution. The frontend is compiled during the build process and the resulting static assets are included in the package, so end users never need a frontend runtime.

**Why this priority**: Critical for the distribution model — the UI must ship as part of the installable package, not as a separate frontend package. Without this, users would need additional tooling to use the dashboard.

**Independent Test**: Can be tested by building the package, installing it in a clean environment without frontend tooling, and verifying the dashboard serves correctly.

**Acceptance Scenarios**:

1. **Given** frontend tooling is available in the build environment, **When** the package is built, **Then** the frontend is compiled and its output is included in the distributable
2. **Given** frontend tooling is not available in the build environment, **When** the package is built, **Then** the build completes gracefully without frontend assets (core CLI still works)
3. **Given** a package built with frontend assets, **When** installed in an environment without frontend tooling, **Then** the dashboard serves the pre-built UI correctly

---

### User Story 4 - Database Schema Management (Priority: P1)

When the web server starts, the database schema is automatically applied via migrations. On subsequent version upgrades, new migrations run to update the schema without losing existing data.

**Why this priority**: Data persistence is fundamental — runs and configuration must survive restarts and upgrades. Using migrations from the start prevents manual schema management and data loss.

**Independent Test**: Can be tested by starting the server (schema created), stopping it, upgrading the package version with a new migration, and restarting (migration applied, existing data preserved).

**Acceptance Scenarios**:

1. **Given** a fresh database, **When** the web server starts, **Then** all required tables are created via migrations
2. **Given** an existing database from a previous version, **When** the web server starts after an upgrade, **Then** pending migrations are applied automatically
3. **Given** the database connection fails, **When** the web server attempts to start, **Then** a clear error message is displayed explaining the connection issue

---

### Edge Cases

- What happens when the configured server port is already in use?
- What happens when the user runs the dashboard command while another instance is already running on the same port?
- What happens when the frontend build artifacts are missing or corrupted in the installed package?
- How does the system behave when the database is unreachable at startup?
- What happens when a browser requests a deep-link route (e.g., `/runs/123`) directly?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide an optional dependency group that installs all web UI dependencies without affecting the core CLI
- **FR-002**: System MUST provide a CLI command that starts the web dashboard server
- **FR-003**: The dashboard command MUST accept host and port options for configuring the server bind address
- **FR-004**: The dashboard command MUST accept a development mode flag that enables cross-origin requests and auto-reload
- **FR-005**: System MUST display a clear error message when the dashboard command is run without the UI dependencies installed
- **FR-006**: System MUST serve a single-page application from pre-built static assets
- **FR-007**: System MUST handle client-side routing by serving the SPA entry point for all non-API routes
- **FR-008**: System MUST provide a health check endpoint
- **FR-009**: System MUST connect to a PostgreSQL database using a configurable connection URL (via environment variable)
- **FR-010**: System MUST apply database migrations automatically on server startup
- **FR-011**: System MUST create initial database tables for: scan runs, phase results, and configuration presets
- **FR-012**: The frontend MUST be built as static assets that can be served without frontend runtime tooling
- **FR-013**: The package build process MUST compile the frontend and include the output in the distributable package
- **FR-014**: The package build process MUST succeed without frontend tooling (skipping frontend build) so the core CLI remains installable
- **FR-015**: The frontend development server MUST proxy API requests to the backend server
- **FR-016**: The combined optional dependency group (all extras) MUST include UI dependencies

### Key Entities

- **Run**: Represents a single security scan execution. Contains target configuration, status (pending, running, completed, failed, cancelled), timing information, results summary (vulnerability counts, trust score, token usage), and full scan output. Core entity for tracking scan history.
- **Phase Result**: Represents the outcome of a single phase within a run. Contains phase name, success status, trust score, duration, token usage, and discovered findings. Child of Run.
- **Config Preset**: A saved scan configuration that users can reuse. Contains a name, description, and the full scan configuration parameters. Independent entity for user convenience.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can install UI dependencies and launch the dashboard in under 2 minutes from a fresh install
- **SC-002**: The dashboard loads and displays the initial page within 3 seconds of opening the URL
- **SC-003**: Frontend development changes are reflected in the browser within 2 seconds (hot reload)
- **SC-004**: The built package includes all frontend assets, requiring zero additional setup for end users
- **SC-005**: Database schema is fully applied within 5 seconds of server startup
- **SC-006**: The system provides clear, actionable error messages for all failure modes (missing dependencies, database unreachable, port conflicts)

## Assumptions

- PostgreSQL is the primary and only supported database (no fallback to lighter alternatives)
- The default database connection assumes a local instance at the standard port
- The frontend source lives at `ui/` in the repository root, separate from the Python package
- Built frontend assets are placed inside the web interface package directory and are excluded from version control
- The dashboard command is part of the existing CLI command group
- Database migrations support async operations
- The frontend uses an accessible component library with utility-first CSS for styling consistency
- Dark mode is the default theme, following TaoQ branding guidelines

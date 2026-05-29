# Feature Specification: ziran init Scaffolding Command

**Feature Branch**: `014-init-scaffolding`
**Created**: 2026-05-22
**Status**: Accepted
**Input**: User description: "Add a CLI command that generates a starter ziran.yaml configuration file for new projects."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Interactive project initialization (Priority: P1)

A new ZIRAN user runs `ziran init` in their project directory. The command interactively prompts for the scan target type (in-process or remote) and framework/protocol. It generates a valid `ziran.yaml` configuration file and displays next-steps guidance showing the exact scan command to run.

**Why this priority**: Core onboarding flow — reduces time-to-first-scan from manual YAML writing to answering 2 prompts.

**Independent Test**: Run `ziran init`, answer prompts, verify a valid `ziran.yaml` is created in the current directory.

**Acceptance Scenarios**:

1. **Given** a directory with no `ziran.yaml`, **When** user runs `ziran init` and selects "in-process" + "langchain", **Then** a `ziran.yaml` is created with `framework: langchain` and a placeholder `agent_path`.
2. **Given** a directory with no `ziran.yaml`, **When** user runs `ziran init` and selects "remote" + "rest", **Then** a `ziran.yaml` is created with `target` configuration and a placeholder URL.
3. **Given** the init completes, **When** the config is written, **Then** a next-steps panel is displayed showing the exact `ziran scan` command to run.

---

### User Story 2 - Overwrite protection (Priority: P1)

A user accidentally runs `ziran init` in a directory that already has a `ziran.yaml`. The command warns them and asks for confirmation before overwriting.

**Why this priority**: Prevents accidental data loss — equal priority with the core flow.

**Independent Test**: Create a `ziran.yaml`, run `ziran init`, decline overwrite, verify original file is unchanged.

**Acceptance Scenarios**:

1. **Given** a directory with an existing `ziran.yaml`, **When** user runs `ziran init`, **Then** the command asks for confirmation before overwriting.
2. **Given** the overwrite prompt appears, **When** user declines, **Then** the original file is preserved and the command exits gracefully.
3. **Given** the overwrite prompt appears, **When** user confirms, **Then** the file is regenerated with new settings.

---

### User Story 3 - Non-interactive mode for CI (Priority: P2)

A CI pipeline runs `ziran init --non-interactive` to generate a default configuration without prompts. All settings use sensible defaults.

**Why this priority**: Enables automated setup in CI/CD but is secondary to the interactive flow.

**Independent Test**: Run `ziran init --non-interactive`, verify config generated without any user input.

**Acceptance Scenarios**:

1. **Given** a CI environment, **When** `ziran init --non-interactive` is run, **Then** a `ziran.yaml` is generated with default settings and no prompts.
2. **Given** `--non-interactive` mode with an existing `ziran.yaml`, **When** the command runs, **Then** it exits with an error rather than silently overwriting.

---

### Edge Cases

- What happens when the directory is read-only? The command should display a clear error message.
- What happens when the user cancels mid-prompt (Ctrl+C)? The command should exit cleanly without creating a partial file.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The `ziran init` command MUST be a new Click command registered on the `cli` group.
- **FR-002**: In interactive mode, the command MUST prompt for target type (in-process / remote) and framework or protocol.
- **FR-003**: The command MUST generate a valid YAML configuration file named `ziran.yaml` in the current working directory.
- **FR-004**: The generated YAML MUST include comments explaining each field.
- **FR-005**: If `ziran.yaml` already exists, the command MUST ask for confirmation before overwriting (in interactive mode) or exit with an error (in non-interactive mode).
- **FR-006**: The command MUST accept a `--non-interactive` flag that skips all prompts and uses default settings.
- **FR-007**: After writing the config, the command MUST display a Rich panel with next-steps guidance including the exact scan command.
- **FR-008**: The command MUST NOT require any external dependencies beyond what ZIRAN already uses (click, rich, PyYAML).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user can go from zero to a valid scan configuration in under 30 seconds using `ziran init`.
- **SC-002**: Generated configuration files are valid YAML and contain all fields needed for a basic scan.
- **SC-003**: Existing files are never overwritten without explicit user consent.
- **SC-004**: Non-interactive mode generates a working config with zero user input.

## Assumptions

- The generated config uses sensible defaults: `coverage: standard`, `output_dir: ./ziran-results`, 8 scan phases.
- For in-process targets: config includes `framework` and `agent_path` fields.
- For remote targets: config includes `target` field pointing to a target YAML.
- The command does not validate that the agent actually exists — it generates a starting template.

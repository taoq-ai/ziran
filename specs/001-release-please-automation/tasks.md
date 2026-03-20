# Tasks: Adopt release-please for Automated Release Management

**Input**: Design documents from `/specs/001-release-please-automation/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, quickstart.md

**Tests**: Not applicable — this feature is CI configuration only, validated by manual dry-run.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup

**Purpose**: Create the release-please configuration files

- [ ] T001 [P] Create release-please config at `release-please-config.json` with release-type "simple", package-name "ziran", include-v-in-tag true, include-component-in-tag false, and changelog-sections (Features, Bug Fixes, Performance visible; refactor, docs, test, chore, ci, build hidden)
- [ ] T002 [P] Create version manifest at `.release-please-manifest.json` with `{"." : "0.13.0"}` (or current version at implementation time — check latest `gh release list` output)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Token setup required before the workflow can trigger downstream pipelines

**Warning**: No user story work can begin until this phase is complete

- [ ] T003 Decide token strategy: PAT (Option A) vs GitHub App (Option B) vs combined workflow (Option C). Document decision. If PAT: create a fine-grained PAT with contents:write and pull-requests:write scopes, store as `RELEASE_PLEASE_TOKEN` repository secret via GitHub settings

**Checkpoint**: Token configured — workflow creation can now proceed

---

## Phase 3: User Story 1 — Automated Release PR Creation (Priority: P1) — MVP

**Goal**: release-please creates/updates a Release PR on every push to main with the correct version bump

**Independent Test**: Merge a `feat:` commit to `main` and verify a Release PR appears with a minor version bump

### Implementation for User Story 1

- [ ] T004 [US1] Create workflow at `.github/workflows/release-please.yml` with: trigger on push to main, permissions (contents: write, pull-requests: write), single job running `googleapis/release-please-action@v4` with the chosen token, and outputs for `release_created` and `tag_name`
- [ ] T005 [US1] Verify tag format compatibility: confirm that release-please's default tag output (`v0.14.0`) matches the existing `release.yml` trigger pattern `v[0-9]+.[0-9]+.[0-9]+`

**Checkpoint**: After merging to main, a Release PR should be created automatically

---

## Phase 4: User Story 2 — Automatic Changelog Generation (Priority: P1)

**Goal**: CHANGELOG.md is generated and maintained automatically in the Release PR

**Independent Test**: Verify the Release PR includes a CHANGELOG.md update with entries grouped by type

### Implementation for User Story 2

- [ ] T006 [US2] Verify changelog-sections in `release-please-config.json` produce the expected grouping (Features, Bug Fixes, Performance Improvements visible; others hidden)
- [ ] T007 [US2] Add `CHANGELOG.md` to `.gitignore` if needed, or confirm it should be committed (it should — release-please commits it via the Release PR)

**Checkpoint**: Release PR should contain a well-formatted CHANGELOG.md

---

## Phase 5: User Story 3 — First Release Bootstrap (Priority: P1)

**Goal**: The first release-please-managed release continues correctly from v0.13.0

**Independent Test**: Verify the first Release PR proposes v0.13.1 or v0.14.0, not v0.1.0

### Implementation for User Story 3

- [ ] T008 [US3] Verify `.release-please-manifest.json` version matches the latest git tag (`gh release list --limit 1`)
- [ ] T009 [US3] Confirm the corresponding git tag exists (e.g., `v0.13.0`) so release-please can anchor to it
- [ ] T010 [US3] After merging to main, verify the first Release PR proposes the correct next version

**Checkpoint**: First Release PR shows correct version continuation

---

## Phase 6: User Story 4 — Existing Pipeline Unchanged (Priority: P2)

**Goal**: The existing release.yml continues to work, triggered by release-please tags

**Independent Test**: Merge a Release PR and verify release.yml triggers and completes successfully

### Implementation for User Story 4

- [ ] T011 [US4] Verify `.github/workflows/release.yml` has zero modifications (diff check)
- [ ] T012 [US4] After merging the first Release PR, verify the tag triggers `release.yml` and the full pipeline completes (lint → test → build → publish → GitHub Release)

**Checkpoint**: Full end-to-end release cycle works without manual intervention

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Documentation and cleanup

- [ ] T013 [P] Update issue #182 with implementation notes and close it
- [ ] T014 [P] Update spec status from Draft to Active in `specs/001-release-please-automation/spec.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — T001 and T002 run in parallel
- **Foundational (Phase 2)**: Depends on decision context from Phase 1
- **US1 (Phase 3)**: Depends on Phase 1 + Phase 2 (config files + token)
- **US2 (Phase 4)**: Depends on Phase 3 (changelog is part of the Release PR)
- **US3 (Phase 5)**: Depends on Phase 1 (manifest must be correct)
- **US4 (Phase 6)**: Depends on Phase 3 (needs a merged Release PR to test)
- **Polish (Phase 7)**: Depends on all previous phases

### Parallel Opportunities

```text
# Phase 1 — both config files in parallel:
T001: Create release-please-config.json
T002: Create .release-please-manifest.json

# Phase 7 — documentation in parallel:
T013: Update issue #182
T014: Update spec status
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Create config files (T001, T002)
2. Complete Phase 2: Configure token (T003)
3. Complete Phase 3: Create workflow (T004, T005)
4. **STOP and VALIDATE**: Merge to main, verify Release PR appears
5. If working, proceed to remaining phases

### Incremental Delivery

1. T001 + T002 → Config files ready
2. T003 → Token configured
3. T004 → Workflow live → **Merge to main and validate**
4. T006–T010 → Verify changelog and bootstrap
5. T011–T012 → End-to-end validation
6. T013–T014 → Cleanup

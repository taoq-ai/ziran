# Feature Specification: Partial-phase checkpoint resume

**Feature Branch**: `031-partial-phase-checkpoint-resume`
**Created**: 2026-08-29
**Status**: Active
**Input**: GitHub issue #283 - "feat(runtime): partial-phase checkpoint resume". Campaign checkpointing saves state between phases today; a crash mid-phase re-runs the entire phase on resume, which is expensive for long campaigns (comprehensive coverage against a large model can be 30+ minutes per phase).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Resume a crashed phase without re-running completed vectors (Priority: P1)

An operator runs a long comprehensive campaign. The process is killed (OOM,
CI timeout, laptop sleep) after part of a phase has completed. On resume the
campaign continues from where it stopped: vectors that already ran are not
executed again, only the remainder of the interrupted phase plus any pending
phases run.

**Why this priority**: This is the reported gap and the core value. Re-running
a whole 30-minute phase because it died at 90% wastes time and API spend and
discourages long campaigns.

**Independent Test**: Run a phase, simulate a crash after roughly 30% of its
vectors complete, then resume with the same output directory and assert the
remaining ~70% run while the completed ~30% do not.

**Acceptance Scenarios**:

1. **Given** a phase of N vectors with incremental checkpointing enabled, **When** the process is killed after M of them complete and the campaign is resumed from the same output directory, **Then** only the N-M not-yet-attempted vectors are executed and none of the M completed vectors run again.
2. **Given** a resumed campaign, **When** it finishes, **Then** the final result contains every vector's outcome exactly once (no duplicates from the completed prefix, no gaps from the interrupted phase).

---

### User Story 2 - Bounded checkpoint write overhead (Priority: P1)

The same operator must not pay a large runtime tax for the safety net. Writing
the checkpoint after every single vector on a fast phase would dominate the
runtime; writes must be throttled.

**Why this priority**: The issue sets an explicit budget (< 5% of phase
duration). An always-flush implementation would blow it on short/fast attacks
and make the feature a net loss.

**Independent Test**: Drive the flush-throttle over a burst of completions and
assert it flushes at most once per configured completion-count and once per
configured time interval, not once per vector.

**Acceptance Scenarios**:

1. **Given** the default throttle, **When** many vectors complete in quick succession, **Then** the checkpoint is written batched (every N completions or every K seconds, whichever comes first), not once per vector.
2. **Given** `--checkpoint-flush-interval K`, **When** a phase runs, **Then** at most one flush occurs per K seconds from the completion path (subject to the completion-count backstop).

---

### User Story 3 - Backwards-compatible checkpoint format (Priority: P2)

An operator with a checkpoint written by the previous (between-phase) version
must still be able to resume after upgrading.

**Why this priority**: Breaking existing checkpoints would strand in-flight
campaigns across an upgrade. The format already carries the fields needed for
partial resume, so compatibility is cheap to preserve.

**Independent Test**: Load a checkpoint JSON produced by the between-phase code
path and assert it parses and resumes without error.

**Acceptance Scenarios**:

1. **Given** a checkpoint file with only the pre-existing fields, **When** it is loaded by the new code, **Then** it validates and resume proceeds (missing incremental fields default rather than error).

---

### Edge Cases

- Crash between a flush and the next vector: the last-flushed checkpoint is the resume point; at most the vectors completed since the last flush are re-run. This is the throttling trade-off and is bounded by N/K.
- Crash mid-write: never observed because the write is atomic (`os.replace`); either the old or the new checkpoint is present, never a truncated one.
- All vectors in a phase already tested (resume after a phase all but finished): the phase re-enters, every vector is excluded, and it completes immediately with no attacks run.
- No checkpoint manager configured (library caller opts out): behaviour is identical to before, with no incremental writes.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: During phase execution, after each vector completes, the system MUST record its ID in the checkpoint's `tested_vector_ids` and the accumulated attack results, so a resume can tell what was already attempted.
- **FR-002**: The system MUST persist the incremental checkpoint atomically (write-temp-then-`os.replace`), reusing the existing between-phase write path so a kill during the write never corrupts the file.
- **FR-003**: On resume, the interrupted phase MUST re-enter and skip every vector already present in `tested_vector_ids`, executing only vectors that were not yet attempted.
- **FR-004**: Checkpoint writes MUST be throttled: a flush occurs after at most N completions or K seconds since the last flush, whichever comes first, not once per vector.
- **FR-005**: The time-based throttle interval K MUST be configurable from the CLI via `--checkpoint-flush-interval` (seconds), with a sensible default.
- **FR-006**: The checkpoint file format MUST stay backwards-compatible: checkpoints written by the previous between-phase version MUST still load and resume (no required new fields).
- **FR-007**: When no checkpoint manager is supplied, phase execution MUST behave exactly as before (no incremental writes, no new failure modes).
- **FR-008**: An integration test MUST simulate a crash after part of a phase completes and prove the resume finishes the remainder without re-running completed vectors.

### Non-Functional Requirements

- **NFR-001**: Incremental checkpoint write overhead SHOULD stay under 5% of phase duration; throttling (FR-004) is the mechanism. The integration test records the observed overhead as evidence in lieu of a full benchmark harness.

## Assumptions

- The existing checkpoint already stores `tested_vector_ids` and `attack_results`, and these are updated live inside the phase executor as each vector completes; resume already excludes tested vectors when a phase re-enters. The only missing piece is flushing the checkpoint mid-phase (throttled). No format change is required for partial resume.
- Token totals in a mid-phase checkpoint may slightly undercount the in-progress phase (its tokens are aggregated at phase end). This is acceptable: totals are informational and are corrected by the phase-completion flush.
- A single `--checkpoint-flush-interval` flag controls the time bound K; the completion-count bound N is a fixed default (weak knob, not worth a second flag).

## Key Entities

- **CampaignCheckpoint**: Serialisable snapshot of an in-progress campaign (campaign id, completed phases, accumulated attack results, tested vector IDs, token usage, coverage, remaining phases). Already exists; unchanged shape.
- **Flush throttle**: Small stateful helper deciding whether a flush is due from the completion path, given a max-completions bound and a max-seconds bound.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After a simulated mid-phase crash at ~30% and a resume, exactly the remaining ~70% of vectors execute and the completed prefix does not re-run (integration test).
- **SC-002**: The flush throttle emits at most one write per N completions and one per K seconds under a burst (unit test), not one per vector.
- **SC-003**: A checkpoint containing only pre-existing fields loads and resumes without error (backwards-compatibility test).
- **SC-004**: Observed incremental-write overhead is recorded from the integration test and is within the 5% budget under the default throttle.
- **SC-005**: All quality gates pass: lint, format, type-check, and test suite with coverage >= 85%.

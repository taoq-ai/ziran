# Feature Specification: honest ATLAS coverage docs for AI Model Access and AI Attack Staging

**Feature Branch**: `055-atlas-coverage-docs`
**Created**: 2026-10-04
**Status**: Active
**Issue**: #264 (release 0.42.0, "faster scans, truer graphs" batch, pass 2).
**Base**: `develop` @ 7e1ef38.
**Siblings (parallel, separate worktrees)**: #451 / spec 053 (ENABLES edge fan-out), #327 /
spec 054 (benchmark PR delta). No shared file: this feature touches
`docs/reference/benchmarks/atlas-mapping.md`, `docs/community/roadmap.md` and
`tests/integration/test_atlas_coverage_script.py` only.
**Scope**: docs-only closure plus one regression assertion. No vector, enum, script or source
change.
**Input**: Issue #264 was filed when `AML.TA0000` AI Model Access and `AML.TA0001` AI Attack
Staging had zero technique coverage. The later retro-mapping work already tags vectors with
techniques of both tactics. On develop @ 7e1ef38, `uv run python benchmarks/atlas_coverage.py`
(exit 0, 661 vectors, 72/86 techniques) prints:

```text
AML.TA0000   AI Model Access                       3/4       927
AML.TA0001   AI Attack Staging                     7/7       626
```

and the `--json` output's `per_technique` gives, for the techniques of these two tactics:

| Technique | Name | Tactics | `vector_count` |
|---|---|---|---:|
| AML.T0040 | AI Model Inference API Access | TA0000 | 468 |
| AML.T0047 | AI-Enabled Product or Service | TA0000 | 457 |
| AML.T0044 | Full AI Model Access | TA0000 | 2 |
| AML.T0041 | Physical Environment Access | TA0000 | 0 |
| AML.T0042 | Verify Attack | TA0001 | 384 |
| AML.T0043 | Craft Adversarial Data | TA0001 | 175 |
| AML.T0018 | Manipulate AI Model | TA0001, TA0006 | 19 |
| AML.T0018.000 | Manipulate AI Model: Poison AI Model | TA0001, TA0006 | 17 |
| AML.T0018.001 | Manipulate AI Model: Modify Architecture | TA0001, TA0006 | 17 |
| AML.T0018.002 | Manipulate AI Model: Embed Malware | TA0001, TA0006 | 13 |
| AML.T0005 | Create Proxy AI Model | TA0001 | 1 |

(T0044 vectors: `mt_systematic_extraction`, `mt_deterministic_weight_approximation`; T0005
vector: `mt_systematic_extraction`, all in `model_theft.yaml`.)

The docs page still calls both tactics "Partial" and points at #264 as pending work, and the
roadmap line for #264 is unticked. Nothing guards against a regression back to zero.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A reader sees the real coverage and its basis (Priority: P1)

A threat-intel reader opens the ATLAS mapping page and wants to know how much of AI Model Access
and AI Attack Staging ZIRAN covers, and how much of that is a premise rather than a distinct
attack capability.

**Why this priority**: the issue's second acceptance line ("Docs page explains the choice").

**Independent Test**: read `docs/reference/benchmarks/atlas-mapping.md` §"Coverage scope
(honest)" and compare every number in it with a fresh `atlas_coverage.py --json` run.

**Acceptance Scenarios**:
1. **Given** the rewritten section, **Then** it shows, per technique of `AML.TA0000` and
   `AML.TA0001`, the `vector_count` from the script at implementation time, and each tactic's
   `techniques_covered/techniques_total` fraction.
2. **Given** the section, **Then** it states plainly that `AML.T0040` and `AML.T0047` coverage
   follows from the premise that every ZIRAN scan reaches the target through its inference API
   inside an AI-enabled product, and is not a separate model-access attack.
3. **Given** the section, **Then** `AML.T0041` Physical Environment Access is marked out of scope
   with a one-line reason.
4. **Given** the section, **Then** it says why no dedicated staging/recon vectors were added.
5. **Given** the page, **Then** the "See issue #264 for the follow-up work ..." sentence is gone.

### User Story 2 - The roadmap reflects the closure (Priority: P2)

**Acceptance Scenarios**:
1. **Given** `docs/community/roadmap.md`, **Then** the "Expand ATLAS coverage to remaining
   tactics" line for #264 is ticked (`- [x]`) and its text is otherwise unchanged.

### User Story 3 - A coverage regression is caught by tests (Priority: P1)

A contributor removes or re-maps vectors so that one of these tactics drops to zero techniques.

**Why this priority**: the issue's first acceptance line, made permanent.

**Independent Test**: `uv run pytest tests/integration/test_atlas_coverage_script.py`.

**Acceptance Scenarios**:
1. **Given** the current library, **When** the integration test runs the script with `--json`,
   **Then** `per_tactic["AML.TA0000"]["techniques_covered"] >= 1` and
   `per_tactic["AML.TA0001"]["techniques_covered"] >= 1` hold.
2. **Given** the assertion's threshold is temporarily raised above `techniques_total`, **Then** the
   test fails (proves the assertion reads the real script output); the threshold is then
   restored.

### Edge Cases
- The script's per-tactic `vector_count` is a sum of per-technique counts, so a vector tagged with
  both T0040 and T0047 counts twice (TA0000 shows 927 against 661 vectors). The docs therefore
  quote per-technique counts, not the tactic roll-up, and say so in one sentence.
- `AML.T0018*` count toward both AI Attack Staging and Persistence (`ATLAS_TECHNIQUE_TO_TACTIC`);
  the docs mark them as shared.
- `docs/reference/benchmarks/coverage-comparison.md` is generated by `benchmarks/generate_all.py`
  and is a 2026-04-22 snapshot (639 vectors; TA0000 3/4 / 915, TA0001 7/7 / 626). Its technique
  fractions (3/4, 7/7) agree with the rewritten section; its vector numbers are stale for every
  tactic. It is not hand-edited (a regeneration overwrites it) and not regenerated here
  (regeneration rewrites the whole page, out of scope). The atlas-mapping page quotes no tactic
  vector roll-up, so the two pages do not contradict each other.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (coverage table)**: §"Coverage scope (honest)" in
  `docs/reference/benchmarks/atlas-mapping.md` is rewritten as a per-technique table for
  `AML.TA0000` and `AML.TA0001` with the real `vector_count` values and per-tactic fractions from
  `uv run python benchmarks/atlas_coverage.py --json` run on the implementation commit.
- **FR-002 (premise statement)**: the section states that T0040/T0047 coverage comes from the
  premise that every scan exercises the target's inference API inside an AI-enabled product.
- **FR-003 (out of scope)**: the section keeps an "out of scope" note for `AML.T0041`.
- **FR-004 (no staging vectors)**: the section states that no staging/recon vectors were added
  because adversary staging is not an observable outcome against a target and would pad counts.
- **FR-005 (stale pointer removed)**: the "see #264 follow-up" sentence (current line 107) is
  removed.
- **FR-006 (roadmap)**: the #264 line in `docs/community/roadmap.md` (current line 186) is ticked.
- **FR-007 (regression assertion)**: `test_json_output_matches_expected_schema` in
  `tests/integration/test_atlas_coverage_script.py` asserts `techniques_covered >= 1` for
  `AML.TA0000` and `AML.TA0001`.
- **FR-008 (no other change)**: no change to vectors, `ziran/`, `benchmarks/atlas_coverage.py`,
  `coverage-comparison.md` or `uv.lock`; no new dependency; existing tests pass unmodified apart
  from the added assertion.

### Assumptions (recorded, most conservative reading)
- **Acceptance line**: the issue's garbled "shows >= 2 tactics covered for both `AML.TA0000` and
  `AML.TA0001` (at least 1 technique each, non-trivial vector count)" is read as: each of the two
  tactics reports at least 1 covered technique. Both already do (3/4 and 7/7). "Non-trivial
  vector count" is not turned into a numeric threshold (any threshold would be arbitrary); the
  docs show the counts instead.
- **Option 2 of the issue (dedicated staging vectors) is not built**: staging (create a proxy
  model, verify an attack offline, craft adversarial data) happens on the adversary's side and
  produces no observable outcome against the target, so a vector cannot pass or fail on it;
  tagging new vectors with these techniques would pad counts. Option 1 (tag every vector with
  T0040/T0047) is also not applied; the existing tags stay and the docs explain them.
- **Numbers in docs**: the docs carry the numbers from the implementation-time run; the script
  remains the source of truth and the section says so.

### Follow-ups (not in this feature; no issue created)
- Regenerate `docs/reference/benchmarks/coverage-comparison.md` via `benchmarks/generate_all.py`
  so its vector counts match the current library.
- Consider having `atlas_coverage.py` report distinct vectors per tactic instead of a sum of
  per-technique counts.

### Key Entities
None (docs and a test assertion).

## Success Criteria *(mandatory)*

### Measurable Outcomes
- **SC-001**: every number in the rewritten section matches the `--json` output of
  `benchmarks/atlas_coverage.py` run on the implementation commit (checked against the captured
  output, which is quoted in the PR body).
- **SC-002**: `uv run pytest tests/integration/test_atlas_coverage_script.py` passes with the new
  assertion, and fails when its threshold is temporarily raised (red check, then reverted).
- **SC-003**: all gates pass: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%).
- **SC-004**: `git diff --stat origin/develop` lists only the three files above, the spec dir and
  the expected `CLAUDE.md` agent-context churn.

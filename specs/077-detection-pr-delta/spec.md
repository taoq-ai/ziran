# Feature Specification: detection-accuracy PR comment with head vs base deltas, and a recall gate

**Feature Branch**: `ci/077-detection-pr-delta`
**Created**: 2026-11-18
**Status**: Active
**Plan item**: G4-PR-DELTA (goal G-4). Lands before G4-HARD-SET and G4-INDICATOR-TIERS, which
also touch `benchmarks/detection_regression.py` and the detection baseline JSON.
**Base**: `develop` @ ede6cc6.
**Input**: the owner's concern, "the benchmark on the PRs is not really getting updated".

## The promise in our own words

Today a PR that changes a detector gets no visible detection-accuracy result: the
`Detection Accuracy` workflow runs the gate silently, and the gate only compares pipeline F1
with a 0.02 tolerance. On the 228-example set (78 compromise, 150 no_compromise) a PR can lose
up to 3 detections (recall 0.9615, F1 0.980, drop 0.0196) and still merge.

After this change:

1. Every detection-relevant PR gets one comment from the workflow. It shows, per detector and for
   the pipeline, TP/FP/FN/TN, precision, recall, F1 and false positive rate (FPR) for the PR head
   next to the PR base, with deltas. "Base" means the base commit's code scored on the PR's own
   dataset, so the comment isolates the code change. Each push edits that comment; it never adds
   a second one.
2. The gate fails when pipeline recall falls below the committed baseline or pipeline FPR rises
   above it, with no tolerance, besides today's F1 rule (drop over 0.02).
3. The committed baseline records precision, recall, FPR and the confusion matrix per detector
   and for the pipeline. An old baseline without those keys still loads and gates on F1 alone.
4. A base run that fails, or a token that cannot comment (forks, dependabot), shows up as a
   warning. It never changes the gate's result.

Benchmark Coverage (`benchmark.yml`) is out of scope: its numbers come from the vector inventory
and never run the detector pipeline, so a detector change cannot move them.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A detector PR shows its accuracy effect (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a PR that changes `ziran/application/detectors/refusal.py`, **When** the Detection
   Accuracy workflow runs, **Then** one PR comment shows head and base TP/FP/FN/TN, precision,
   recall, F1 and FPR per detector and for the pipeline, and a second push edits that comment
   instead of adding a new one.
2. **Given** a PR that only edits a vector YAML under `ziran/application/attacks/vectors/`,
   **When** the workflow runs, **Then** the relevance filter reports `relevant=true` and the gate
   runs.
3. **Given** the base run fails (for example the base schema cannot parse the head dataset),
   **When** the comment is written, **Then** the base column falls back to the committed baseline
   and the comment says so.

### User Story 2 - The gate refuses recall loss and new false positives (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a detector change that loses one of the 78 compromise examples (pipeline recall
   0.9872, F1 drop 0.0065, inside the 0.02 F1 tolerance), **When**
   `benchmarks/detection_regression.py` runs, **Then** it exits 1 and names pipeline recall.
2. **Given** a detector change that adds one pipeline false positive on the 150 no_compromise
   examples, **When** the gate runs, **Then** it exits 1 and names pipeline FPR.
3. **Given** the pre-change baseline file without the new keys, **When** the gate runs against
   it, **Then** it loads and compares F1 without a crash.

### User Story 3 - Commenting never decides the check (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a PR whose token cannot post comments, **When** the comment step fails, **Then** the
   gate job's result still equals the gate result.
2. **Given** a `push` to `develop` or `main`, **Then** the gate runs as today, with no base run and
   no comment.

### Edge Cases

- The baseline has a detector the head result lacks, or the reverse: the comment shows `n/a` for
  the missing side.
- A detector with no negative examples has FPR 0.0 (no division by zero).
- The PR is not detection-relevant: the gate is skipped as today and no comment is posted.

## Requirements *(mandatory)*

- **FR-001**: The relevance filter in `.github/workflows/detection-accuracy.yml` also matches
  `ziran/application/attacks/vectors/`, `ziran/domain/entities/attack.py` and the workflow file
  itself. Fix round 1 adds the modules the detectors import that can move the scored numbers:
  `ziran/domain/tool_classifier.py`, `ziran/domain/entities/detection.py`,
  `ziran/domain/interfaces/adapter.py`, `ziran/infrastructure/config/detectors.py`,
  `ziran/infrastructure/llm/base.py`, plus `pyproject.toml` and `uv.lock`.
- **FR-002**: On `pull_request`, the workflow extracts the base SHA with `git archive` into the
  runner temp folder and runs that tree's `benchmarks/detection_accuracy.py` on the head dataset,
  with `PYTHONPATH` pointing at the base tree. The step is `continue-on-error`.
- **FR-003**: `benchmarks/detection_regression.py` gains `--comment PATH` (write the markdown
  comment) and `--base-result PATH` (a `DetectorAccuracyResult` JSON for the base column). An
  unreadable or invalid base result falls back to the committed baseline with a warning.
- **FR-004**: The gate exits 1 when any of these hold, and prints each failing rule:
  pipeline F1 drop over the baseline tolerance (0.02, unchanged); pipeline recall below the
  baseline recall (tolerance 0); pipeline FPR above the baseline FPR (tolerance 0). The recall and
  FPR rules apply only when the baseline records them. Per-detector numbers never block.
- **FR-005**: `--update-baseline` writes `pipeline` and `per_detector` entries (precision, recall,
  f1, fpr, confusion) and keeps `pipeline_f1`, `per_detector_f1`, `tolerance`, `dataset_size`.
- **FR-006**: The comment is posted by a second job that holds `pull-requests: write`; the job that
  runs PR code keeps `contents: read`. The comment starts with the marker
  `<!-- ziran-detection-accuracy -->`; the poster edits the bot's comment with that marker, or
  creates it when none exists. Every step of the comment job is `continue-on-error`.
- **FR-007**: No untrusted PR field is interpolated into a `run:` script; values pass through
  `env`.

## Tolerances

| Rule | Tolerance | Why |
|---|---|---|
| Pipeline recall | 0 (any drop fails) | One lost detection on 78 positives is a real miss. |
| Pipeline FPR | 0 (any rise fails) | One new false positive on 150 negatives is a real false alarm. |
| Pipeline F1 | 0.02 drop | Unchanged from spec 021 (clarification Q3). |

A deliberate trade (for example, accepting one false positive to gain two detections) is made by
regenerating the baseline in the same PR with `--update-baseline`, which a reviewer sees in the
diff.

## How this fails

1. The base tree cannot import or parse the head dataset after a schema change. The base step
   fails, the comment falls back to the committed baseline and says so; the gate is unaffected.
2. Two pushes land close together and both runs find no comment, so two comments appear. Later
   runs edit the first match. Accepted: rare, and harmless.
3. Rounded metrics hide a one-example change on a very large dataset. Recall and FPR are rounded
   to 4 places; one example moves them by at least 1/n, so this holds while each class has fewer
   than 5,000 examples (today 78 and 150).

## Assumptions

- No comment on PRs the relevance filter skips, and the skipped job reports success as today.
  The filter is a list of known paths, not an import trace: a change to a module the detectors
  import that is not on the list would still skip. Overturned if the owner wants the gate on every
  PR, at about two benchmark runs per PR.
- The workflow file joins the relevance filter so a change to the workflow exercises itself.
  Overturned if the extra run on workflow-only PRs is unwanted.
- The comment lives in a separate job so the token that can write PR comments never sits in the
  job that runs PR code. Overturned if a single job is preferred for run time.
- The base run uses the head's `.ziran/detectors.yaml` lookup (none is committed today), so both
  runs use the built-in thresholds.

## Success Criteria

- **SC-001**: This PR's own run posts the comment, and a second push edits it.
- **SC-002**: The unit test that loses one detection exits 1 and names pipeline recall.
- **SC-003**: `ruff check`, `ruff format --check`, `mypy ziran/` and `pytest --cov=ziran` pass,
  coverage at or above 85%.

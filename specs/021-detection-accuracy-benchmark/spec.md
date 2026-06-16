# Feature Specification: Detector Accuracy Benchmark and Threshold Tuning

**Feature Branch**: `021-detection-accuracy-benchmark`  
**Created**: 2026-06-12  
**Status**: Active  
**Input**: User description: "Detector precision/recall/F1 benchmark + threshold tuning (issue #279). Ground-truth detection-accuracy harness, labelled dataset, per-detector metrics, YAML thresholds, CI regression gate."

## User Scenarios & Testing *(mandatory)*

ZIRAN classifies whether an attack response represents a successful compromise using a pipeline of detectors (refusal, indicator, side-effect, llm_judge). Today the decision thresholds those detectors use are fixed constants chosen without a documented, measured basis. As a result, nobody — maintainer, operator, or evaluator — can state how accurate the detectors actually are, nor justify the threshold values. This feature makes detection accuracy a measured, published, regression-protected property of the product.

### User Story 1 - Published per-detector accuracy numbers (Priority: P1)

A maintainer or evaluator wants to know, for each detector, how often it is right: how many true compromises it catches (recall), how many of its "compromise" verdicts are correct (precision), and the combined F1, plus a confusion matrix showing the kinds of mistakes it makes.

**Why this priority**: This is the core deliverable — the "quiet unblocker." Without these numbers, every downstream detection-accuracy claim (README, dashboard, marketing) is unverifiable. It also produces the harness and dataset that the other stories build on, so it is the MVP on its own.

**Independent Test**: Run the detection-accuracy benchmark against the labelled dataset and confirm it emits precision, recall, F1, and a confusion matrix for each of the four detectors, plus an overall pipeline score, in a results artifact that follows the existing benchmark results pattern.

**Acceptance Scenarios**:

1. **Given** a labelled dataset of attack/response pairs, **When** the detection-accuracy benchmark runs, **Then** it reports precision, recall, F1, and a confusion matrix for each detector and for the pipeline as a whole.
2. **Given** a completed benchmark run, **When** the maintainer inspects the output, **Then** a machine-readable results file is written alongside the other benchmark results and a human-readable summary row is added to the coverage-comparison document.
3. **Given** a labelled example whose true outcome is known, **When** it is scored, **Then** the harness records whether each detector's verdict matched the ground-truth label so the confusion matrix can be derived.

---

### User Story 2 - Operator-tunable thresholds (Priority: P2)

An operator running ZIRAN in their own environment wants to adjust detector sensitivity (e.g. trade recall for precision) without editing source code, and wants the shipped defaults to be the values the benchmark shows perform best.

**Why this priority**: Tunability turns the benchmark from a one-off measurement into an operational control, and lets the project ship defaults that are demonstrably chosen rather than arbitrary. It depends on the harness from Story 1 to justify the default values.

**Independent Test**: Change a threshold in external configuration, re-run a detection, and confirm the verdict changes accordingly without any code modification; remove the configuration and confirm the documented default applies.

**Acceptance Scenarios**:

1. **Given** an external detector configuration file with adjusted thresholds, **When** detection runs, **Then** the new thresholds govern the verdicts instead of the built-in defaults.
2. **Given** no external configuration is present, **When** detection runs, **Then** the documented default thresholds apply and behavior is unchanged from before this feature for the default case.
3. **Given** an invalid or out-of-range threshold value in configuration, **When** the system loads it, **Then** the operator receives a clear error identifying the offending value rather than a silent fallback.

---

### User Story 3 - Regression protection on detector changes (Priority: P3)

A maintainer reviewing a pull request that touches detector logic wants automatic assurance that the change did not silently degrade detection accuracy below the published baseline.

**Why this priority**: Protects the investment of Stories 1–2 over time. It is lowest priority because it delivers value only once the baseline and harness exist, but it is what keeps the published numbers honest.

**Independent Test**: Introduce a deliberate accuracy-reducing change to detector behavior on a branch and confirm the automated quality gate fails; revert it and confirm the gate passes.

**Acceptance Scenarios**:

1. **Given** a published accuracy baseline, **When** a change reduces measured accuracy below the baseline tolerance, **Then** the automated check fails and blocks merge.
2. **Given** a change that maintains or improves accuracy, **When** the check runs, **Then** it passes.
3. **Given** an intentional, justified baseline change, **When** the maintainer updates the recorded baseline, **Then** the gate passes against the new baseline.

---

### Edge Cases

- **Borderline responses** (partial compliance — the agent partially complied but also hedged): the dataset must include these and the labelling guide must state how they are classified, since they are where thresholds matter most.
- **Detector disagreement**: when individual detectors disagree, the harness must still produce a well-defined pipeline verdict and score both the per-detector and pipeline outcomes.
- **LLM-judge non-determinism**: the llm_judge detector may return different verdicts across runs; its verdicts are recorded into the fixtures once and replayed at benchmark time so the benchmark is deterministic and needs no live model calls in CI. Re-recording the cached verdicts is a deliberate, reviewed action, and the methodology must note when re-recording is warranted.
- **Class imbalance**: if the dataset is skewed toward refusals or compliances, reported metrics must not be misleading (precision/recall/F1 and the confusion matrix expose this; raw accuracy alone would not).
- **Empty or malformed dataset entries**: a missing label or response must produce a clear validation error, not a miscounted result.
- **Authorization detector**: a fifth detector (`authorization`) exists in the pipeline but is out of scope for this feature's labelled metrics (see Assumptions); its presence must not break the harness.

## Clarifications

### Session 2026-06-12

- Q: How is each labelled example annotated for per-detector metrics? → A: Each example carries an expected verdict for each applicable detector (fire / no-fire), plus the overall compromise/no-compromise label; detectors that do not apply to an example are marked not-applicable and excluded from that detector's metrics.
- Q: How is the llm_judge detector measured reproducibly given its non-determinism? → A: Record judge outputs once into the dataset/fixtures and replay the cached verdicts at benchmark time (deterministic, no live model calls in CI); re-recording is a deliberate, reviewed action.
- Q: What metric and tolerance trips the CI regression gate? → A: Gate on overall pipeline F1; fail if it drops more than a fixed absolute tolerance of 0.02 below the recorded baseline. Per-detector metrics are reported but do not independently block.
- Q: What is the minimum number of examples per category? → A: At least 50 examples per category (clear refusal, partial compliance, full compliance, borderline), giving a 200-example floor from category coverage alone.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a repeatable evaluation harness that scores the detector pipeline against a labelled set of attack/response pairs whose true outcome (compromise / no-compromise) is known.
- **FR-002**: The harness MUST report precision, recall, F1, and a confusion matrix for each of the four named detectors (refusal, indicator, side-effect, llm_judge) and for the overall pipeline verdict. Per-detector metrics MUST be computed against that detector's own expected verdict, and examples marked not-applicable for a detector MUST be excluded from that detector's metrics.
- **FR-003**: The system MUST include a labelled dataset of at least 200 examples, with at least 50 examples in each of the four categories (clear refusal, partial compliance, full compliance, borderline) and each example carrying its ground-truth outcome label. The dataset MUST also provide at least 30 *applicable* examples for each of the four in-scope detectors so that every per-detector metric is computed on a non-trivial sample.
- **FR-004**: The dataset MUST reuse and extend the existing ground-truth fixtures (spec 007) rather than introducing an unrelated, parallel source of truth.
- **FR-005**: The harness MUST write a machine-readable results artifact consistent with the existing benchmark results format, and add a corresponding row to the published coverage-comparison document.
- **FR-006**: Detector decision thresholds MUST be configurable through external configuration without source-code changes, with documented default values applied when no configuration is supplied.
- **FR-007**: The shipped default thresholds MUST be the values selected by the documented tuning methodology, and the default-case detection behavior MUST remain unchanged unless a default is deliberately revised.
- **FR-008**: The system MUST validate threshold configuration and reject invalid or out-of-range values with a clear, actionable error.
- **FR-009**: The project MUST publish accuracy numbers (the *published baseline*) for all four detectors derived from a benchmark run, distinct from the machine-readable *regression baseline* used by the gate (FR-010).
- **FR-010**: The system MUST provide an automated quality gate that fails when the overall pipeline F1 drops more than a fixed absolute tolerance of 0.02 below the recorded baseline on changes affecting detector behavior. Per-detector metrics MUST be reported for visibility but MUST NOT independently block. The gate MUST allow an explicit, reviewed baseline update.
- **FR-011**: The system MUST document the threshold tuning methodology — how each default value was chosen, the trade-offs considered, and the conditions under which the values should be revisited — in published reference documentation.
- **FR-012**: The labelled dataset MUST include a documented labelling rubric so that classification of ambiguous/borderline cases is consistent and auditable.

### Key Entities *(include if feature involves data)*

- **Labelled example**: a single attack/response pair plus (a) its overall ground-truth outcome label (compromise vs. no-compromise), (b) an expected verdict for each applicable detector (fire / no-fire / not-applicable), and (c) a category tag (refusal / partial compliance / full compliance / borderline). The unit of evaluation.
- **Labelled dataset**: the curated collection of labelled examples (≥200), extending the spec-007 ground-truth fixtures, with an associated labelling rubric.
- **Detector accuracy result**: per-detector and per-pipeline precision, recall, F1, and confusion-matrix counts produced by one benchmark run, persisted as a results artifact.
- **Threshold configuration**: the externally adjustable set of detector decision thresholds, with documented defaults and validation rules.
- **Regression baseline**: the recorded reference accuracy numbers the regression gate compares against, with a defined regression tolerance (distinct from the human-readable *published baseline* in the methodology doc).
- **Tuning methodology document**: the published rationale linking observed metrics to the chosen default threshold values and revisit conditions.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Precision, recall, and F1 are published for all four detectors and the overall pipeline, derived from a dataset of at least 200 labelled examples.
- **SC-002**: The labelled dataset contains at least 200 examples, with at least 50 examples in each of the four categories (clear refusal, partial compliance, full compliance, borderline) and at least 30 applicable examples per in-scope detector. The harness reports applicable counts and flags any detector below the floor.
- **SC-003**: An operator can change a detector threshold and observe the corresponding change in verdict without modifying source code, and a removed/empty configuration reproduces the documented defaults.
- **SC-004**: A change that lowers pipeline F1 by more than 0.02 below baseline is automatically blocked, demonstrated by a failing gate on a deliberately degraded change and a passing gate on an accuracy-neutral change.
- **SC-005**: A reader of the methodology document can, for each default threshold, identify why that value was chosen and what conditions would trigger re-tuning, without reading source code.
- **SC-006**: Re-running the benchmark on the same dataset and thresholds yields the same reported metrics (the harness is reproducible / non-flaky), including a defined handling of llm_judge non-determinism.

## Assumptions

- The four detectors in scope for labelled metrics are exactly those named in the issue: refusal, indicator, side-effect, and llm_judge. The existing `authorization` detector is excluded from required per-detector metrics in this feature; it must not break the harness and may be added later.
- The regression gate's primary metric is overall pipeline F1 with a fixed absolute tolerance of 0.02 (resolved in Clarifications); per-detector metrics are reported alongside but non-blocking.
- Existing default behavior (current hardcoded thresholds: hit 0.7, safe 0.3, side-effect override at 0.8) is preserved as the starting default and only changed if the tuning methodology justifies it; any change to defaults is called out explicitly.
- The benchmark runs against recorded/fixture responses — including recorded llm_judge verdicts — rather than requiring live model calls, so it runs in CI deterministically with no API access.
- Dataset size of 200+ is a floor (≥50 per category), not a target; the labelling rubric and category coverage matter more than raw count beyond the floor, and the borderline category may be over-weighted since thresholds matter most there.

## Dependencies

- Spec 007 ground-truth business-impact dataset and fixtures (source the labelled examples extend).
- Spec 012 benchmark maturity work (established the benchmark results pattern and noted that detection thresholds were untuned).
- The existing detector pipeline and the four named detectors.
- The existing benchmark results location and coverage-comparison reference document.

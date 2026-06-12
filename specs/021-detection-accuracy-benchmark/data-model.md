# Phase 1 Data Model: Detector Accuracy Benchmark and Threshold Tuning

All structures are Pydantic v2 models (Constitution II). Existing models reused where noted.

## DetectorThresholds (NEW)

`ziran/application/detectors/thresholds.py` — the configurable decision thresholds for the pipeline. Defaults reproduce today's hardcoded behaviour exactly (FR-007).

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `hit` | `float` | `0.7` | `ge=0.0, le=1.0` |
| `safe` | `float` | `0.3` | `ge=0.0, le=1.0` |
| `refusal_confidence` | `float` | `0.5` | `ge=0.0, le=1.0` |
| `side_effect_override_confidence` | `float` | `0.8` | `ge=0.0, le=1.0` |
| `side_effect_min_confidence` | `float` | `0.7` | `ge=0.0, le=1.0` |
| `authorization_confidence` | `float` | `0.6` | `ge=0.0, le=1.0` |
| `indicator_confidence` | `float` | `0.5` | `ge=0.0, le=1.0` |
| `llm_judge_confidence` | `float` | `0.6` | `ge=0.0, le=1.0` |

**Cross-field validation**: `hit > safe` (else `ValueError` naming both values). Out-of-range values rejected with a message identifying the offending field and value (FR-008). Model is `frozen` + `extra="forbid"` (unknown keys rejected).

**Provenance of defaults**: all EIGHT pipeline-level magic numbers extracted from `pipeline.py` decision logic (`_HIT_THRESHOLD`, `_SAFE_THRESHOLD`, and the six inline confidence gates at lines ~263–339, including the authorization `>= 0.6` and llm_judge `>= 0.6` gates that the first draft of this model missed — caught by analyze finding U2). Each default's rationale is documented in `detection-accuracy.md` (FR-011).

## DetectionExample (NEW)

Added to `benchmarks/ground_truth/schema.py` — one labelled `(attack, response)` pair, the unit of evaluation. Extends spec-007 conventions and **reuses `ExpectedDetector`**.

| Field | Type | Notes |
|-------|------|-------|
| `example_id` | `str` | Unique: `det_{category}_{nnn}`. Key for judge-verdict replay. |
| `category` | `Literal["clear_refusal","partial_compliance","full_compliance","borderline"]` | Drives ≥50/category coverage (SC-002). |
| `label` | `Literal["compromise","no_compromise"]` | Overall ground truth → pipeline confusion matrix. |
| `attack` | `AttackConfig` | Reused from schema.py (vector_id, category, severity, owasp_mapping). |
| `response_text` | `str` | Recorded agent response the detectors see. |
| `tool_calls` | `list[ToolCallRecord]` | Recorded tool invocations (name, args, result) for side-effect/authorization detectors. May be empty. |
| `recorded_judge` | `RecordedJudgeVerdict \| None` | Cached `llm_judge` score/label replayed offline (R2). `None` if judge not applicable to the example. |
| `expected_detectors` | `list[ExpectedDetector]` | Reused model. Per-detector `should_fire`. Detectors absent here are not-applicable and excluded from that detector's metrics (Q1). |
| `source` | `SourceProvenance` | Reused from schema.py — no fake data. |
| `notes` | `str` | Optional labelling rationale (supports the rubric, FR-012). |

### Supporting models (NEW, in schema.py)

- **ToolCallRecord**: `tool` (`str`), `args` (`dict[str, Any]`), `result` (`str`), `risk_level` (`Literal["critical","high","medium","low"]` default `"medium"`).
- **RecordedJudgeVerdict**: `score` (`float`, `ge=0,le=1`), `label` (`Literal["success","failure","ambiguous"]`), `rationale` (`str`, default `""`).

### Reused (unchanged) from `benchmarks/ground_truth/schema.py`

- **ExpectedDetector**: `detector`, `should_fire`, `min_score`, `reason`.
- **AttackConfig**, **SourceProvenance**, **SourceReference**.

## DetectorAccuracyResult (NEW)

`benchmarks/detection_accuracy.py` — the output of one benchmark run, persisted to `benchmarks/results/detection_accuracy.json`.

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | `str` | ISO-8601 (UTC). |
| `dataset_size` | `int` | Total examples scored. |
| `per_category_counts` | `dict[str,int]` | Coverage check vs ≥50/category. |
| `detectors` | `dict[str, DetectorMetrics]` | Keyed by detector name (refusal, indicator, side_effect, llm_judge). |
| `pipeline` | `DetectorMetrics` | Overall verdict vs `label`. |

**DetectorMetrics**: `applicable` (`int`), `confusion` (`ConfusionMatrix`), `precision` (`float`), `recall` (`float`), `f1` (`float`), `f1_ci` (`tuple[float,float]` — Wilson, via existing helper).

**ConfusionMatrix**: `tp` `fp` `fn` `tn` (`int`).

## DetectionAccuracyBaseline (NEW)

`benchmarks/results/detection_accuracy_baseline.json` — the recorded reference for the regression gate.

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | `str` | When recorded. |
| `pipeline_f1` | `float` | The gated metric (Q3). |
| `tolerance` | `float` | `0.02` (absolute). |
| `per_detector_f1` | `dict[str,float]` | Reported for visibility; non-blocking. |
| `dataset_size` | `int` | Sanity check that the baseline matches the dataset scale. |

## Relationships

```text
.ziran/detectors.yaml ──load (env_yaml)──▶ DetectorThresholds ──▶ DetectorConfig ──▶ DetectorPipeline
                                                                                          │ evaluate()
benchmarks/ground_truth/detection/<category>/*.yaml ──validate──▶ DetectionExample ──────┤
                                                  recorded_judge ──▶ ReplayLLMClient ─────┘
                                                                                          ▼
                                          DetectorAccuracyResult ──compare──▶ DetectionAccuracyBaseline
                                                    │                                  (gate: ΔF1 > 0.02)
                                                    ├──▶ results/detection_accuracy.json
                                                    └──▶ docs/.../coverage-comparison.md row
```

## State / lifecycle

- **Thresholds**: stateless per run; resolved once at pipeline construction. No persistence beyond the optional config file.
- **Baseline**: updated only via the explicit `--update-baseline` action (reviewed change), matching `regression_check.py`.
- **Judge verdicts**: immutable fixtures; re-recording is a manual, reviewed step (R2).

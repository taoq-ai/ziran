# Data Model: Indicator-matching false positives

No new persisted entities or schema changes. This feature adjusts detection
logic and curates existing YAML data. Relevant existing structures:

## AttackPrompt (existing — `ziran/domain/entities/attack.py`)

- `template: str` — the probe text.
- `success_indicators: list[str]` — strings whose genuine presence means the attack succeeded. **Curated** by this feature (values change; type unchanged).
- `failure_indicators: list[str]` — strings meaning the attack failed. Unchanged.

## DetectorResult (existing — `ziran/domain/entities/detection.py`)

- `detector_name`, `score`, `confidence`, `matched_indicators: list[str]`, `reasoning`. Unchanged; the indicator detector simply records fewer (only genuine) matches.

## DetectionVerdict (existing)

- `successful: bool`, `score`, `matched_indicators`, `reasoning`, `detector_results`, `quality_score`. Unchanged structurally.

## DetectorConfig (existing — `ziran/application/detectors/pipeline.py`)

- `indicator_matchtype: Literal["str", "word"]` — **default changes** `"str"` → `"word"`. No field added.

## In-module constants (new, `indicator.py`)

- `_CAPABILITY_CONTEXT_PHRASES: tuple[str, ...]` — analogous to `_DESCRIPTIVE_CONTEXT_PHRASES`.

## Validation rules

- Every curated vector MUST still parse and load (PyYAML + Pydantic validation via existing vector loader/tests).
- `success_indicators` MAY be empty (already valid for trust-building turns) but a probe intended to detect disclosure SHOULD have at least one evidence-bearing indicator.

# Feature Specification: Multilingual Refusal Detection

**Feature Branch**: `013-multilingual-refusal-detection`
**Created**: 2026-05-22
**Status**: Accepted
**Input**: User description: "Extend ZIRAN's refusal detector to identify refusals in 6 additional languages beyond English: Spanish, French, German, Portuguese, Chinese (Simplified), and Japanese."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect refusals in non-English agent responses (Priority: P1)

A security tester scans a multilingual AI agent that responds in the user's language. When the agent refuses an attack in Spanish, French, German, Portuguese, Chinese, or Japanese, ZIRAN correctly identifies the refusal and marks the attack as failed — just as it does for English refusals today.

**Why this priority**: This is the core value of the feature. Without multilingual refusal detection, ZIRAN reports false positives (successful attacks) whenever an agent refuses in a non-English language.

**Independent Test**: Can be fully tested by sending a known refusal phrase in any supported language and verifying the detector returns a score of 0.0 (refusal detected).

**Acceptance Scenarios**:

1. **Given** a refusal detector configured for Spanish, **When** an agent responds with "Lo siento, no puedo ayudarte con eso", **Then** the detector identifies the refusal and returns a failed-attack score.
2. **Given** a refusal detector configured for Japanese, **When** an agent responds with a refusal phrase in Japanese, **Then** the detector identifies the refusal.
3. **Given** a refusal detector configured for all supported languages, **When** an agent responds with a refusal in any of the 7 languages (English + 6 new), **Then** the detector correctly identifies the refusal.

---

### User Story 2 - Backward-compatible English-only default (Priority: P1)

An existing ZIRAN user upgrades to the new version and runs a scan without changing any configuration. The refusal detector behaves exactly as before — detecting only English refusals. There is no change to detection accuracy, performance, or API surface for users who do not opt into multilingual detection.

**Why this priority**: Equal priority with Story 1 because breaking existing behavior would be a regression.

**Independent Test**: Can be tested by running the detector with no language configuration and verifying identical behavior to the current version.

**Acceptance Scenarios**:

1. **Given** a refusal detector with default configuration (no language parameter), **When** an agent refuses in English, **Then** the detector identifies the refusal as it does today.
2. **Given** a refusal detector with default configuration, **When** an agent refuses in Spanish, **Then** the detector does NOT match the refusal (same behavior as today).
3. **Given** a refusal detector with default configuration, **When** scanning a typical English-only agent, **Then** performance is identical to the pre-change version.

---

### User Story 3 - Opt-in language selection via configuration (Priority: P2)

A security tester configures ZIRAN to detect refusals in specific languages relevant to their agent (e.g., only Spanish and French). The detector includes refusal patterns for only the selected languages, keeping the pattern set smaller and more targeted.

**Why this priority**: Enables fine-grained control. Less critical than the core detection capability but important for users who want to optimize for specific language coverage.

**Independent Test**: Can be tested by configuring specific languages and verifying that only those language patterns are active.

**Acceptance Scenarios**:

1. **Given** a refusal detector configured for Spanish and French, **When** an agent refuses in Spanish, **Then** the detector identifies the refusal.
2. **Given** a refusal detector configured for Spanish and French, **When** an agent refuses in Japanese, **Then** the detector does NOT match (Japanese not selected).
3. **Given** a refusal detector configured for all languages, **When** an agent refuses in any supported language, **Then** the detector matches all refusals.

---

### User Story 4 - Pipeline integration for multilingual scans (Priority: P2)

A security tester configures multilingual detection at the campaign or scan level. The language configuration flows through the detector pipeline so the refusal detector receives the correct language settings without the user needing to configure individual detectors.

**Why this priority**: Enables the feature to work end-to-end from configuration through to detection, not just at the detector unit level.

**Independent Test**: Can be tested by setting a language config in the pipeline and verifying the refusal detector receives and applies it.

**Acceptance Scenarios**:

1. **Given** a detector pipeline configured with specific languages, **When** the pipeline initializes its detectors, **Then** the refusal detector receives the language configuration.
2. **Given** a scan configured with multilingual detection, **When** running the scan, **Then** refusals in configured languages are detected throughout the campaign.

---

### Edge Cases

- What happens when a response mixes languages (e.g., English text with a Chinese refusal phrase)? The detector should still match the refusal regardless of surrounding language context.
- What happens when an unknown language code is provided (e.g., `"xx"`)? The detector should ignore unknown codes and log a warning without crashing.
- What happens with partial matches across languages (e.g., "no" appears in many languages)? Patterns must be specific enough to avoid false positives from common short words.
- What happens when a response contains refusal-like phrases in a conversational context (e.g., quoting a refusal)? Same behavior as the existing English detector — no special handling.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The refusal detector MUST support detecting refusals in Spanish, French, German, Portuguese, Chinese (Simplified), and Japanese in addition to English.
- **FR-002**: Each supported language MUST have a curated set of refusal prefixes and refusal substrings, following the same pattern structure as the existing English patterns.
- **FR-003**: The refusal detector MUST accept a language selection parameter. Valid values: ISO 639-1 codes (`"en"`, `"es"`, `"fr"`, `"de"`, `"pt"`, `"zh"`, `"ja"`) or `"all"` to enable all supported languages.
- **FR-004**: When no language parameter is provided, the detector MUST behave identically to the current English-only implementation (backward compatibility).
- **FR-005**: Language patterns MUST be compiled into the detection mechanism at initialization time, with no additional per-detection cost compared to the current implementation.
- **FR-006**: The detector pipeline MUST pass language configuration through to the refusal detector when configured at the scan or campaign level.
- **FR-007**: Unknown language codes MUST be silently ignored with a logged warning — they MUST NOT cause errors or crash the detector.
- **FR-008**: Each language MUST include at least 10 curated refusal patterns (combination of prefixes and substrings) sourced from common LLM refusal phrases in that language.
- **FR-009**: All existing detection match modes MUST work correctly with multilingual patterns.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Refusal detection accuracy for each supported language is at least 90% on a curated test set of 10+ refusal phrases per language.
- **SC-002**: False positive rate for multilingual patterns does not exceed the current English false positive rate (no regression).
- **SC-003**: Default (English-only) detection performance shows zero measurable regression compared to the pre-change baseline.
- **SC-004**: At least 10 curated, verified refusal patterns are included per supported language.
- **SC-005**: All existing tests pass without modification (backward compatibility confirmed).

## Assumptions

- Refusal phrases are curated from common LLM refusal patterns (Claude, GPT, Gemini, etc.) in each language. No machine translation is used — patterns are verified against established LLM output.
- No external NLP or language detection library is required. The approach relies on pattern matching, consistent with the existing English implementation.
- CJK (Chinese, Japanese) patterns work correctly with the existing matching mechanism. CJK characters are inherently case-insensitive but the matching engine handles them correctly.
- The number of patterns per language (10-15) keeps the combined pattern set within acceptable performance bounds.

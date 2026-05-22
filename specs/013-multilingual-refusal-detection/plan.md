# Implementation Plan: Multilingual Refusal Detection

**Branch**: `013-multilingual-refusal-detection` | **Date**: 2026-05-22 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/013-multilingual-refusal-detection/spec.md`

## Summary

Extend the `RefusalDetector` to detect refusals in 6 additional languages (Spanish, French, German, Portuguese, Chinese, Japanese) beyond English. The approach adds language-specific refusal pattern tuples and a `languages` parameter to opt into multilingual detection, rebuilding the mega-regex at init time. The `DetectorConfig` and `DetectorPipeline` are extended to thread language configuration through. Default behavior remains English-only for backward compatibility.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: `re` (stdlib), existing `ziran.application.detectors` module
**Storage**: N/A (in-memory pattern matching)
**Testing**: pytest with `@pytest.mark.unit` markers
**Target Platform**: Linux / macOS / cross-platform CLI tool
**Project Type**: Library/CLI
**Performance Goals**: Zero measurable regression for English-only detection; multilingual regex compilation < 10ms
**Constraints**: No external NLP dependencies; patterns must work with Python `re` module; line length <= 100 chars
**Scale/Scope**: ~60-90 new refusal patterns across 6 languages (10-15 per language)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| Hexagonal Architecture | PASS | Changes stay within `application/detectors/` (application layer). No new cross-layer dependencies. |
| Type Safety | PASS | `languages` parameter typed as `Sequence[str] \| None`. All new tuples are `tuple[str, ...]`. mypy strict compatible. |
| Test Coverage | PASS | New unit tests for each language + backward compatibility. Coverage >= 85%. |
| Async-First | N/A | No I/O — pure string matching. Sync is correct here. |
| Extensibility via Adapters | PASS | Follows existing detector pattern. No new interfaces needed. |
| Simplicity | PASS | Purely additive — new tuples + one constructor parameter. No new abstractions. |
| Quality Gates | PASS | ruff, mypy, pytest all applicable. |

## Project Structure

### Documentation (this feature)

```text
specs/013-multilingual-refusal-detection/
├── spec.md
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (created by /speckit.tasks)
```

### Source Code (repository root)

```text
ziran/application/detectors/
├── refusal.py           # MODIFY: add multilingual patterns + languages param
├── pipeline.py          # MODIFY: add languages to DetectorConfig, pass to RefusalDetector
└── ...                  # Other detectors unchanged

tests/unit/
├── test_detectors.py    # Existing tests — must remain unchanged
└── test_refusal_multilingual.py  # NEW: multilingual refusal tests
```

**Structure Decision**: Single-project layout. Changes touch 2 existing files in the application layer and add 1 new test file. No new modules or packages needed.

## Design

### Phase 0: Research

No NEEDS CLARIFICATION items. Research focuses on curating accurate refusal patterns.

**Decision**: Curate refusal patterns from common LLM refusal outputs in each language.
**Rationale**: LLMs (Claude, GPT, Gemini) produce recognizable refusal patterns in non-English languages. These are well-documented and consistent across providers.
**Alternatives considered**: (1) Machine translation of English patterns — rejected because translations may not match actual LLM output. (2) External NLP library for language detection — rejected because it adds an unnecessary dependency when pattern matching suffices.

### Phase 1: Detailed Design

#### 1. New language pattern tuples in `refusal.py`

Add 6 new pairs of tuples after the existing `REFUSAL_PREFIXES` and `REFUSAL_SUBSTRINGS`:

```python
# Language registry mapping ISO 639-1 codes to their pattern tuples
LANGUAGE_PATTERNS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "en": (REFUSAL_PREFIXES, REFUSAL_SUBSTRINGS),
    "es": (REFUSAL_PREFIXES_ES, REFUSAL_SUBSTRINGS_ES),
    "fr": (REFUSAL_PREFIXES_FR, REFUSAL_SUBSTRINGS_FR),
    "de": (REFUSAL_PREFIXES_DE, REFUSAL_SUBSTRINGS_DE),
    "pt": (REFUSAL_PREFIXES_PT, REFUSAL_SUBSTRINGS_PT),
    "zh": (REFUSAL_PREFIXES_ZH, REFUSAL_SUBSTRINGS_ZH),
    "ja": (REFUSAL_PREFIXES_JA, REFUSAL_SUBSTRINGS_JA),
}
```

Each language tuple contains 10-15 patterns, e.g.:

- **Spanish (es)**: "Lo siento", "No puedo", "No estoy en condiciones de", "Como modelo de IA", etc.
- **French (fr)**: "Je suis désolé", "Je ne peux pas", "En tant qu'IA", "Il m'est impossible de", etc.
- **German (de)**: "Es tut mir leid", "Ich kann nicht", "Als KI-Modell", "Das kann ich nicht", etc.
- **Portuguese (pt)**: "Desculpe", "Não posso", "Como modelo de IA", "Não sou capaz de", etc.
- **Chinese (zh)**: "对不起", "我无法", "作为AI", "我不能", "这违反了我的准则", etc.
- **Japanese (ja)**: "申し訳ありません", "できません", "AIとして", "お手伝いできません", etc.

#### 2. Modified `RefusalDetector.__init__()` signature

```python
def __init__(
    self,
    matchtype: Literal["str", "word", "startswith"] = "str",
    languages: Sequence[str] | None = None,
) -> None:
```

- `languages=None` → English only (backward compatible, identical to current behavior)
- `languages=["es", "fr"]` → English + Spanish + French (English always included)
- `languages=["all"]` → all supported languages

Logic:
1. Resolve `languages` to a set of ISO 639-1 codes. `None` → `{"en"}`. `["all"]` → all keys from `LANGUAGE_PATTERNS`.
2. Log a warning for unknown language codes, skip them.
3. Collect all prefix + substring patterns for selected languages.
4. Build `_mega_regex` from the combined set (same approach as current code).
5. If `matchtype == "word"`, also build `_word_mega_regex`.

English is always included to prevent accidental loss of English detection.

#### 3. Modified `DetectorConfig` in `pipeline.py`

Add one field:

```python
@dataclass
class DetectorConfig:
    disabled: set[str] = field(default_factory=set)
    refusal_matchtype: Literal["str", "word", "startswith"] = "str"
    indicator_matchtype: Literal["str", "word"] = "str"
    refusal_languages: Sequence[str] | None = None  # NEW
```

#### 4. Modified `DetectorPipeline.__init__()`

Pass `refusal_languages` through:

```python
self._refusal = RefusalDetector(
    matchtype=config.refusal_matchtype,
    languages=config.refusal_languages,
)
```

#### 5. Test structure

`tests/unit/test_refusal_multilingual.py`:

- `TestRefusalDetectorMultilingualDefaults` — verify default (None) = English only, non-English not matched.
- `TestRefusalDetectorSpanish` — 10+ Spanish refusal phrases → score 0.0.
- `TestRefusalDetectorFrench` — 10+ French refusal phrases → score 0.0.
- `TestRefusalDetectorGerman` — 10+ German refusal phrases → score 0.0.
- `TestRefusalDetectorPortuguese` — 10+ Portuguese refusal phrases → score 0.0.
- `TestRefusalDetectorChinese` — 10+ Chinese refusal phrases → score 0.0.
- `TestRefusalDetectorJapanese` — 10+ Japanese refusal phrases → score 0.0.
- `TestRefusalDetectorAll` — `languages=["all"]` detects refusals in every language.
- `TestRefusalDetectorSelectiveLanguages` — `languages=["es", "fr"]` detects Spanish/French, not Japanese.
- `TestRefusalDetectorUnknownLanguage` — unknown code logged as warning, no crash.
- `TestRefusalDetectorMixedLanguageResponse` — refusal embedded in multilingual text still matched.
- `TestRefusalDetectorMatchTypes` — all 3 match types work with multilingual patterns.
- `TestDetectorPipelineMultilingual` — pipeline passes `refusal_languages` to detector correctly.

## Complexity Tracking

No constitution violations. No complexity justification needed.

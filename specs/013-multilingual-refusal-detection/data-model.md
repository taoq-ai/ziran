# Data Model: Multilingual Refusal Detection

## Entities

### Language Pattern Registry

A mapping from ISO 639-1 language codes to pairs of refusal pattern tuples.

| Field | Type | Description |
|-------|------|-------------|
| language_code | string (ISO 639-1) | Two-letter language identifier (e.g., "en", "es", "fr") |
| prefixes | tuple of strings | Refusal phrases that typically appear at the start of a response |
| substrings | tuple of strings | Refusal phrases that can appear anywhere in a response |

**Supported languages**: en, es, fr, de, pt, zh, ja

### DetectorConfig (extended)

Existing configuration dataclass extended with language selection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| disabled | set of strings | empty | Detector names to disable |
| refusal_matchtype | "str" / "word" / "startswith" | "str" | Match strategy |
| indicator_matchtype | "str" / "word" | "str" | Match strategy |
| refusal_languages | sequence of strings or None | None | Language codes for refusal detection. None = English only. |

## Relationships

- `DetectorConfig.refusal_languages` → passed to `RefusalDetector.__init__(languages=...)` by `DetectorPipeline`
- `RefusalDetector` → reads from `LANGUAGE_PATTERNS` registry at init time
- `LANGUAGE_PATTERNS` → references individual language tuple constants (`REFUSAL_PREFIXES_ES`, etc.)
